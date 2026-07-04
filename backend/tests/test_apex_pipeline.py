import pytest
import json
from unittest.mock import AsyncMock

from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import Target, Finding, ApexPipelineState, Job
from core.apex_coordinator import run_phase1_recon, run_phase2_llm, run_phase3_injection, run_apex_pipeline


@pytest.mark.asyncio
async def test_apex_pipeline_state_transitions(monkeypatch):
    # Mock broadcast callback
    broadcasted_messages = []
    async def mock_broadcast(msg):
        broadcasted_messages.append(msg)

    # 1. Setup target and job inside database
    async with AsyncSessionLocal() as session:
        target = Target(name="APEX Transition Target", host="apex-test.local", port=80)
        session.add(target)
        await session.commit()
        target_id = target.id

        job = Job(target_id=target_id, tool_name="APEX Engine", command="APEX Engine")
        session.add(job)
        await session.commit()
        job_id = job.id

    try:
        target_url = "http://apex-test.local"

        # 2. Execute Phase 1: Recon
        await run_phase1_recon(target_id, target_url, job_id, mock_broadcast)

        # Assert Phase 1 creates records in 'cloud_ingested' state
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ApexPipelineState).where(ApexPipelineState.target_url == target_url)
            )
            records = result.scalars().all()
            assert len(records) == 3
            for r in records:
                assert r.pipeline_state == "cloud_ingested"

        # 3. Execute Phase 2: LLM payload generation
        # Mock local LLM endpoint to return clean mutation payloads
        async def mock_post(self, url, json=None, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {"response": '[{"parameter": "id", "value": "1"}]'}
            return MockResponse()

        monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

        await run_phase2_llm(target_url, job_id, mock_broadcast)

        # Assert Phase 2 transitions records to 'payloads_generated'
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ApexPipelineState).where(ApexPipelineState.target_url == target_url)
            )
            records = result.scalars().all()
            assert len(records) == 3
            for r in records:
                assert r.pipeline_state == "payloads_generated"
                assert r.oast_token is not None
                payloads = json.loads(r.generated_payloads)
                assert len(payloads) == 1
                assert payloads[0]["parameter"] == "id"

        # 4. Execute Phase 3: Injection & Verification
        # Mock HTTP client requests in Phase 3
        class MockResponse:
            async def text(self):
                return "ok"
            async def __aenter__(self):
                return self
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
            status = 200

        def mock_request(self, method, url, **kwargs):
            return MockResponse()

        monkeypatch.setattr("aiohttp.ClientSession.request", mock_request)

        await run_phase3_injection(target_id, target_url, job_id, mock_broadcast)

        # Assert Phase 3 transitions matched correlation tokens to 'exploit_verified'
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ApexPipelineState).where(ApexPipelineState.target_url == target_url)
            )
            records = result.scalars().all()
            # Since mock matches the first token, at least one record should transition
            states = [r.pipeline_state for r in records]
            assert "exploit_verified" in states
            assert "injection_complete" in states

            # Check that a verified Finding was stored in the database
            res_findings = await session.execute(
                select(Finding).where(Finding.target_id == target_id)
            )
            findings = res_findings.scalars().all()
            assert len(findings) == 1
            assert findings[0].severity == "Critical"
            assert findings[0].status == "confirmed"

    finally:
        # Clean up database records
        async with AsyncSessionLocal() as session:
            # Delete job
            j_obj = await session.get(Job, job_id)
            if j_obj:
                await session.delete(j_obj)
            # Delete target
            t_obj = await session.get(Target, target_id)
            if t_obj:
                await session.delete(t_obj)
            # Delete state records
            res = await session.execute(
                select(ApexPipelineState).where(ApexPipelineState.target_url == target_url)
            )
            for r in res.scalars().all():
                await session.delete(r)
            await session.commit()
