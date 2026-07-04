import json
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, OOBCanary, Target, Vulnerability, gen_id


class FakeResponse:
    def __init__(self, status_code=200, json_body=None, text=""):
        self.status_code = status_code
        self._json_body = json_body or {}
        self.text = text
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._json_body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.mark.asyncio
async def test_generate_canary_payload_persists_oob_canary(monkeypatch):
    from core.oob_tracker import generate_canary_payload

    monkeypatch.setenv("OOB_BASE_DOMAIN", "oob.test")

    domain = await generate_canary_payload("https://victim.local/profile", "X-Forwarded-For")

    assert domain.endswith(".oob.test")

    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(OOBCanary).where(OOBCanary.target_url == "https://victim.local/profile"))).scalars().all()
        assert len(rows) == 1
        canary = rows[0]
        assert canary.parameter == "X-Forwarded-For"
        assert canary.canary_domain == domain
        assert canary.status == "pending"
        await session.delete(canary)
        await session.commit()


@pytest.mark.asyncio
async def test_poll_remote_oob_server_maps_interaction_to_vulnerability(monkeypatch):
    from core import oob_tracker

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "oob_tracker"))
        canary = OOBCanary(
            id=gen_id(),
            correlation_id="abc123",
            canary_domain="abc123.oob.test",
            target_url="https://victim.local/fetch",
            parameter="Referer",
            status="pending",
        )
        session.add(canary)
        await session.commit()
        canary_id = canary.id

    class FakeClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            return FakeResponse(
                json_body={
                    "interactions": [
                        {
                            "correlation_id": "abc123",
                            "protocol": "dns",
                            "remote_address": "203.0.113.10",
                            "raw_request": "abc123.oob.test A lookup",
                        }
                    ]
                }
            )

    monkeypatch.setenv("OOB_POLL_URL", "https://oob.example/poll")
    monkeypatch.setattr(oob_tracker.httpx, "AsyncClient", FakeClient)

    stats = await oob_tracker.poll_remote_oob_server()

    assert stats == {"interactions": 1, "matched": 1, "created": 1}
    async with AsyncSessionLocal() as session:
        canary = await session.get(OOBCanary, canary_id)
        assert canary.status == "triggered"
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "oob_tracker"))).scalars().all()
        assert len(vulns) == 1
        assert vulns[0].severity == "high"
        assert vulns[0].vuln_type == "SSRF/Blind XSS"
        assert "Referer" in vulns[0].evidence
        await session.delete(canary)
        await session.delete(vulns[0])
        await session.commit()


@pytest.mark.asyncio
async def test_dlp_parser_injects_oob_headers(monkeypatch):
    import core.dlp_parser as dlp_parser

    captured = {}

    async def fake_generate(url, parameter, **kwargs):
        return f"{parameter.lower().replace('-', '')}.oob.test"

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            captured.update(headers or {})
            return FakeResponse(text="<html></html>")

    monkeypatch.setattr(dlp_parser, "generate_canary_payload", fake_generate)
    monkeypatch.setattr(dlp_parser.httpx, "AsyncClient", FakeClient)
    await dlp_parser.analyze_url_telemetry("missing-url", "https://victim.local", "missing-target")

    assert captured["X-Forwarded-For"] == "xforwardedfor.oob.test"
    assert captured["Referer"] == "referer.oob.test"
    assert captured["Contact"] == "contact.oob.test"


@pytest.mark.asyncio
async def test_takeover_profiler_flags_vulnerable_cname(monkeypatch):
    from core import takeover_profiler

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "takeover_profiler"))
        target = Target(id=gen_id(), name="Takeover", host="example.local")
        session.add(target)
        await session.commit()
        target_id = target.id

    async def fake_resolve(subdomain):
        return "dangling.github.io"

    async def fake_probe(url):
        return 404

    monkeypatch.setattr(takeover_profiler, "resolve_cname", fake_resolve)
    monkeypatch.setattr(takeover_profiler, "probe_http_status", fake_probe)

    result = await takeover_profiler.profile_subdomain_takeover("orphan.example.local", target_id)

    assert result["vulnerable"] is True
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "takeover_profiler"))).scalars().all()
        db_target = await session.get(Target, target_id)
        assert len(vulns) == 1
        assert vulns[0].vuln_type == "Subdomain Takeover"
        assert vulns[0].severity == "high"
        await session.delete(vulns[0])
        await session.delete(db_target)
        await session.commit()


@pytest.mark.asyncio
async def test_graphql_fuzzer_persists_sensitive_introspection(monkeypatch):
    from core import graphql_fuzzer

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "graphql_fuzzer"))
        target = Target(id=gen_id(), name="GraphQL", host="api.local")
        session.add(target)
        await session.commit()
        target_id = target.id

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None):
            return FakeResponse(
                json_body={
                    "data": {
                        "__schema": {
                            "types": [
                                {"name": "Query"},
                                {"name": "Mutation"},
                                {"name": "CreateUserMutation"},
                            ]
                        }
                    }
                }
            )

    monkeypatch.setattr(graphql_fuzzer.httpx, "AsyncClient", FakeClient)

    results = await graphql_fuzzer.fuzz_graphql_introspection("https://api.local", target_id)

    assert results[0]["schema_exposed"] is True
    assert "CreateUserMutation" in results[0]["mutations"]
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "graphql_fuzzer"))).scalars().all()
        db_target = await session.get(Target, target_id)
        assert len(vulns) == 1
        assert vulns[0].vuln_type == "GraphQL Introspection"
        assert vulns[0].severity == "high"
        assert "CreateUserMutation" in json.dumps(vulns[0].raw_data)
        await session.delete(vulns[0])
        await session.delete(db_target)
        await session.commit()
