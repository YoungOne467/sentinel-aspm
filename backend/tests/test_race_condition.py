import pytest
from sqlalchemy import delete, select

from core.database import AsyncSessionLocal
from core.models import Vulnerability
from core.race_condition import test_race_condition as run_race_condition_probe


class FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": "application/json"}


class FakeHTTP2Client:
    init_kwargs = None
    calls = []
    responses = []

    def __init__(self, **kwargs):
        type(self).init_kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method, url, **kwargs):
        type(self).calls.append((method, url, kwargs))
        return type(self).responses.pop(0)


@pytest.mark.asyncio
async def test_race_condition_dispatches_twenty_http2_requests_and_persists_anomaly(monkeypatch):
    from core import race_condition

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "race_condition_engine"))
        await session.commit()

    FakeHTTP2Client.calls = []
    FakeHTTP2Client.responses = [
        *[FakeResponse(200, '{"ok": true}') for _ in range(3)],
        *[FakeResponse(400, '{"error": "already redeemed"}') for _ in range(17)],
    ]
    monkeypatch.setattr(race_condition.httpx, "AsyncClient", FakeHTTP2Client)

    result = await run_race_condition_probe(
        "https://app.local/api/coupon/redeem",
        "POST",
        {"Authorization": "Bearer token"},
        {"coupon": "ONCE"},
    )

    assert FakeHTTP2Client.init_kwargs["http2"] is True
    assert len(FakeHTTP2Client.calls) == 20
    assert all(call[0] == "POST" for call in FakeHTTP2Client.calls)
    assert all(call[1] == "https://app.local/api/coupon/redeem" for call in FakeHTTP2Client.calls)
    assert all(call[2]["headers"]["Authorization"] == "Bearer token" for call in FakeHTTP2Client.calls)
    assert all(call[2]["json"] == {"coupon": "ONCE"} for call in FakeHTTP2Client.calls)
    assert result["anomaly_detected"] is True
    assert result["severity"] == "high"
    assert result["status_counts"] == {200: 3, 400: 17}

    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(Vulnerability).where(Vulnerability.source == "race_condition_engine")
            )
        ).scalars().all()
        assert len(rows) == 1
        vulnerability = rows[0]
        assert vulnerability.vuln_type == "Race Condition"
        assert vulnerability.severity == "high"
        assert vulnerability.ai_triage_pending is True
        assert "3 successful responses" in vulnerability.evidence
        await session.delete(vulnerability)
        await session.commit()


@pytest.mark.asyncio
async def test_race_condition_does_not_persist_uniform_failures(monkeypatch):
    from core import race_condition

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "race_condition_engine"))
        await session.commit()

    FakeHTTP2Client.calls = []
    FakeHTTP2Client.responses = [FakeResponse(400, '{"error": "already used"}') for _ in range(20)]
    monkeypatch.setattr(race_condition.httpx, "AsyncClient", FakeHTTP2Client)

    result = await run_race_condition_probe(
        "https://app.local/api/coupon/redeem",
        "POST",
        {},
        {"coupon": "ONCE"},
    )

    assert len(FakeHTTP2Client.calls) == 20
    assert result["anomaly_detected"] is False

    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(Vulnerability).where(Vulnerability.source == "race_condition_engine")
            )
        ).scalars().all()
        assert rows == []
