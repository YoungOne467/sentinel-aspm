import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import json
import httpx
from sqlalchemy import select
from pydantic import ValidationError

from core.database import AsyncSessionLocal, batch_writer
from core.models import Target, CrawledURL, Finding
from core.schemas import AttackPlan, AttackAction
from core.cognitive_engine import CognitiveEngineService, Dispatcher


@pytest.mark.asyncio
async def test_cognitive_engine_service_telemetry_analysis():
    # 1. Insert a mock Target and CrawledURL into the test DB
    async with AsyncSessionLocal() as session:
        t = Target(name="Cognitive Test Target", host="cog.local", port=80, tech_stack=["fastapi"])
        session.add(t)
        await session.commit()
        target_id = t.id

        cu = CrawledURL(target_id=target_id, host="cog.local", url="http://cog.local/api/v1/data", method="POST", status_code=200)
        session.add(cu)
        await session.commit()

    try:
        # 2. Build the expected AttackPlan response from the mocked LLM
        expected_plan = AttackPlan(
            actions=[
                AttackAction(
                    target_element="/api/v1/data",
                    logic_flaw_hypothesis="The endpoint accepts unvalidated SQL parameters",
                    action_type="FUZZ_PARAMETER",
                    generated_payload="1' OR '1'='1"
                )
            ]
        )

        # 3. Instantiate engine and mock the instructor client's structured completion
        service = CognitiveEngineService()
        with patch.object(
            service._instructor_client.chat.completions,
            "create",
            new=AsyncMock(return_value=expected_plan)
        ):
            plan = await service.analyze_target_telemetry(target_id)
            
            assert plan is not None
            assert len(plan.actions) == 1
            assert plan.actions[0].target_element == "/api/v1/data"
            assert plan.actions[0].action_type == "FUZZ_PARAMETER"
            assert plan.actions[0].generated_payload == "1' OR '1'='1"

    finally:
        # Clean up database
        async with AsyncSessionLocal() as session:
            await session.delete(await session.get(CrawledURL, cu.id))
            await session.delete(await session.get(Target, target_id))
            await session.commit()


@pytest.mark.asyncio
async def test_cognitive_engine_validation_error_handling():
    async with AsyncSessionLocal() as session:
        t = Target(name="Cognitive Fallback Target", host="cog-err.local", port=80)
        session.add(t)
        await session.commit()
        target_id = t.id

    try:
        service = CognitiveEngineService()
        
        # Simulate ValidationError raised by instructor on malformed structure
        def raise_val_error(*args, **kwargs):
            raise ValidationError.from_exception_data(
                title="AttackPlan",
                line_errors=[{"type": "missing", "loc": ("actions",), "input": {}}]
            )

        with patch.object(
            service._instructor_client.chat.completions,
            "create",
            side_effect=raise_val_error
        ), patch("core.orchestrator.orchestrator._broadcast_msg", new=AsyncMock()) as mock_broadcast:
            plan = await service.analyze_target_telemetry(target_id, job_id="test-job-id")
            assert plan is None
            mock_broadcast.assert_called_once()
            assert mock_broadcast.call_args[0][0]["type"] == "terminal_output"
            assert "LLM Schema Hallucination" in mock_broadcast.call_args[0][0]["line"]

    finally:
        async with AsyncSessionLocal() as session:
            await session.delete(await session.get(Target, target_id))
            await session.commit()


@pytest.mark.asyncio
async def test_dispatcher_execution_and_findings():
    # 1. Insert mock Target and CrawledURL
    async with AsyncSessionLocal() as session:
        t = Target(name="Dispatcher Test Target", host="disp.local", port=80)
        session.add(t)
        await session.commit()
        target_id = t.id

        cu = CrawledURL(target_id=target_id, host="disp.local", url="http://disp.local/vuln-path", method="POST")
        session.add(cu)
        await session.commit()

    try:
        # 2. Build mock AttackPlan
        plan = AttackPlan(
            actions=[
                AttackAction(
                    target_element="/vuln-path",
                    logic_flaw_hypothesis="Parameter fuzzed reflecting database error",
                    action_type="FUZZ_PARAMETER",
                    generated_payload="1' OR '1'='1"
                )
            ]
        )

        # Mock the HTTP response from target to trigger SQL injection signature
        mock_target_resp = MagicMock()
        mock_target_resp.status_code = 500
        mock_target_resp.text = "Error: database_error - SQL syntax error in query near OR"
        mock_target_resp.headers = {"Content-Type": "text/html"}

        mock_client = AsyncMock()
        mock_client.request.return_value = mock_target_resp

        # 3. Run dispatcher
        dispatcher = Dispatcher(concurrency_limit=2)
        
        with patch("core.http_pool.HTTPClientPool.get_client", new=AsyncMock(return_value=mock_client)):
            # Clear writer buffer first to isolate
            await batch_writer.flush()
            
            await dispatcher.dispatch_plan(target_id, plan)

            # Assertions: check if a finding was enqueued and written
            async with AsyncSessionLocal() as session:
                res = await session.execute(select(Finding).where(Finding.target_id == target_id))
                findings = res.scalars().all()
                assert len(findings) == 1
                assert findings[0].severity == "critical"
                assert "SQL Injection" in findings[0].title
                assert findings[0].status == "confirmed"

                # Cleanup finding
                await session.delete(findings[0])
                await session.commit()

    finally:
        # Clean up database target and crawled URL
        async with AsyncSessionLocal() as session:
            await session.delete(await session.get(CrawledURL, cu.id))
            await session.delete(await session.get(Target, target_id))
            await session.commit()


@pytest.mark.asyncio
async def test_cognitive_ai_recon_job_routing():
    from core.schemas import JobCreate
    from services.scanner import create_job_service
    from core.models import Job

    async with AsyncSessionLocal() as session:
        t = Target(name="Routing Test Target", host="rout.local", port=80)
        session.add(t)
        await session.commit()
        target_id = t.id

    try:
        # Mock run_cognitive_pipeline in services.scanner so we don't trigger actual LLM requests
        with patch("services.scanner.run_cognitive_pipeline", new=AsyncMock()) as mock_run_pipeline:
            req = JobCreate(target_id=target_id, scan_profile="Cognitive AI Recon")
            
            async with AsyncSessionLocal() as session:
                res = await create_job_service(req, session)
                
            assert res["status"] == "queued"
            assert "job_id" in res
            
            job_id = res["job_id"]
            mock_run_pipeline.assert_called_once_with(job_id, target_id)

            # Assert database has the Job record
            async with AsyncSessionLocal() as session:
                job = await session.get(Job, job_id)
                assert job is not None
                assert job.tool_name == "Cognitive AI Recon"
                
                # Cleanup job
                await session.delete(job)
                await session.commit()

    finally:
        async with AsyncSessionLocal() as session:
            target_obj = await session.get(Target, target_id)
            if target_obj:
                await session.delete(target_obj)
            await session.commit()

