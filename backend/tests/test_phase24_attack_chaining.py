import pytest
from sqlalchemy import delete, select

from core.database import AsyncSessionLocal
from core.models import Target, Vulnerability, gen_id


@pytest.mark.asyncio
async def test_secret_extractor_saves_jwt_to_exploit_context_and_chains_vulnerability(monkeypatch):
    from core.attack_chainer import exploit_context
    from core.secret_extractor import analyze_static_asset_for_secrets

    exploit_context.clear()
    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "secret_extractor"))
        target = Target(id=gen_id(), name="Chain", host="api.chain.local")
        session.add(target)
        primary = Vulnerability(
            id=gen_id(),
            target_id=target.id,
            vuln_type="Local File Inclusion (LFI)",
            severity="high",
            title="LFI leaked config",
            source="lfi_module",
        )
        session.add(primary)
        await session.commit()
        target_id = target.id
        primary_id = primary.id

    async def fake_jwt_probe(*args, **kwargs):
        return {"vulnerable": False}

    monkeypatch.setattr("core.secret_extractor.test_jwt_algorithm_downgrade", fake_jwt_probe)
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.signature"

    findings = await analyze_static_asset_for_secrets(
        f'JWT="{jwt}"',
        "https://api.chain.local/config.env",
        target_id=target_id,
        source_vuln_id=primary_id,
    )

    assert any(finding["type"] == "JWT" for finding in findings)
    auth_headers = exploit_context.get_auth_headers("https://api.chain.local/admin")
    assert auth_headers == {"Authorization": f"Bearer {jwt}"}
    assert exploit_context.get_primary_vuln_id("https://api.chain.local/admin") == primary_id

    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "secret_extractor"))).scalars().all()
        assert len(vulns) == 1
        assert vulns[0].chained_from_vuln_id == primary_id
        await session.execute(delete(Vulnerability).where(Vulnerability.target_id == target_id))
        target = await session.get(Target, target_id)
        await session.delete(target)
        await session.commit()


@pytest.mark.asyncio
async def test_scanner_client_injects_exploit_context_auth_when_request_has_no_auth(monkeypatch):
    from core.attack_chainer import exploit_context
    from core import http_client

    monkeypatch.setenv("OOB_INJECTION_ENABLED", "0")
    exploit_context.clear()
    exploit_context.save_secret(
        "https://api.pivot.local",
        {
            "type": "JWT",
            "secret": "eyJhbGciOiJIUzI1NiJ9.payload.signature",
            "source_vuln_id": "primary-vuln",
        },
    )
    seen_headers = []

    async def fake_super_request(self, method, url, *args, **kwargs):
        seen_headers.append(kwargs.get("headers") or {})
        return http_client.httpx.Response(200, text="ok", request=http_client.httpx.Request(method, url))

    monkeypatch.setattr(http_client.httpx.AsyncClient, "request", fake_super_request)
    async def fake_sleep(*_args, **_kwargs):
        pass
    monkeypatch.setattr(http_client.asyncio, "sleep", fake_sleep)

    async with http_client.ScannerAsyncClient(jitter_enabled=False) as client:
        await client.get("https://api.pivot.local/admin")

    assert seen_headers
    assert seen_headers[0]["Authorization"] == "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"


@pytest.mark.asyncio
async def test_stateful_idor_persists_chained_primary_reference(monkeypatch):
    from core import stateful_idor

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "stateful_idor"))
        await session.commit()

    class FakeResponse:
        status_code = 200
        content = b'{"id":1234,"owner":"user-a"}'

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            return FakeResponse()

    monkeypatch.setattr(stateful_idor.httpx, "AsyncClient", FakeClient)

    await stateful_idor.test_stateful_idor(
        ["https://api.local/api/users/1234"],
        {"Authorization": "Bearer token-a"},
        {"Authorization": "Bearer token-b"},
        chained_from_vuln_id="primary-vuln",
    )

    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "stateful_idor"))).scalars().all()
        assert len(vulns) == 1
        assert vulns[0].chained_from_vuln_id == "primary-vuln"
        await session.delete(vulns[0])
        await session.commit()
