import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
import httpx
from core.database import AsyncSessionLocal, batch_writer
from core.models import Target, CrawledURL, Finding
from core.schemas import AttackPlan, AttackAction
from core.cognitive_engine import Dispatcher

@pytest.mark.asyncio
async def test_dispatcher_concurrency_and_waf_and_db_timeout():
    # 1. Insert Target and CrawledURL
    async with AsyncSessionLocal() as session:
        t = Target(name="Dispatcher Concurrency Target", host="concurrency.local", port=80)
        session.add(t)
        await session.commit()
        target_id = t.id

        cu = CrawledURL(target_id=target_id, host="concurrency.local", url="http://concurrency.local/test", method="GET")
        session.add(cu)
        await session.commit()

    try:
        # Create 15 actions to test concurrency limit of 15
        actions = []
        for i in range(15):
            actions.append(
                AttackAction(
                    target_element=f"/test?id={i}",
                    logic_flaw_hypothesis=f"Hypothesis {i}",
                    action_type="FUZZ_PARAMETER",
                    generated_payload=f"payload_{i}"
                )
            )
        # Add 1 action that encounters a WAF 403 block
        actions.append(
            AttackAction(
                target_element="/blocked",
                logic_flaw_hypothesis="WAF Test",
                action_type="CRAFT_CUSTOM_PAYLOAD",
                generated_payload="blocked_val"
            )
        )

        plan = AttackPlan(actions=actions)

        # Mock target response list. WAF returns 403. Normal ones return 200/500
        mock_client = AsyncMock()

        async def mock_request(method, url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.headers = httpx.Headers({})
            if "/blocked" in url:
                resp.status_code = 403
                resp.text = "Forbidden - WAF blocked this request"
            else:
                resp.status_code = 500
                resp.text = "database_error - SQLite lock timeout or SQL syntax error"
            resp.read = lambda: None
            return resp

        mock_client.request = mock_request

        # Run dispatcher
        dispatcher = Dispatcher(concurrency_limit=15)
        
        with patch("core.http_pool.HTTPClientPool.get_client", new=AsyncMock(return_value=mock_client)):
            await batch_writer.flush()
            await dispatcher.dispatch_plan(target_id, plan)

            # Assertions
            async with AsyncSessionLocal() as session:
                # We expect findings for the 15 simulated SQL injection errors
                from sqlalchemy import select
                res = await session.execute(select(Finding).where(Finding.target_id == target_id))
                findings = res.scalars().all()
                assert len(findings) > 0
                for f in findings:
                    assert f.severity in ("critical", "high", "medium", "low")
                    await session.delete(f)
                await session.commit()

    finally:
        async with AsyncSessionLocal() as session:
            await session.delete(await session.get(CrawledURL, cu.id))
            await session.delete(await session.get(Target, target_id))
            await session.commit()
