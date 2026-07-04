import base64
import json
import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import delete, select

from core.database import AsyncSessionLocal
from core.models import Target, Vulnerability, gen_id


class FakeHTTPResponse:
    def __init__(self, text="", status_code=200, headers=None, content=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content if content is not None else text.encode("utf-8")


def make_jwt() -> str:
    def encode(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encode({'alg': 'HS256', 'typ': 'JWT'})}.{encode({'sub': 'user-1'})}.signature"


@pytest.mark.asyncio
async def test_smuggling_probe_flags_http1_desync_anomaly(monkeypatch):
    from core import smuggling_probe

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "smuggling_probe"))
        await session.commit()

    responses = [
        {"status_code": 200, "elapsed": 0.12, "timed_out": False, "raw": "HTTP/1.1 200 OK"},
        {"status_code": 502, "elapsed": 0.18, "timed_out": False, "raw": "HTTP/1.1 502 Bad Gateway"},
    ]

    async def fake_send(url, payload, timeout=6.0):
        assert "HTTP/1.1" in payload
        return responses.pop(0)

    monkeypatch.setattr(smuggling_probe, "send_raw_http1_payload", fake_send)

    result = await smuggling_probe.test_desync("https://smuggle.local/cart")

    assert result["vulnerable"] is True
    assert {probe["attack"] for probe in result["probes"]} == {"CL.TE", "TE.CL"}
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "smuggling_probe"))).scalars().all()
        assert len(vulns) == 1
        assert vulns[0].severity == "high"
        assert vulns[0].vuln_type == "HTTP Request Smuggling"
        assert "TE.CL" in vulns[0].evidence
        await session.delete(vulns[0])
        await session.commit()


@pytest.mark.asyncio
async def test_jwt_downgrader_forges_alg_none_and_persists(monkeypatch):
    from core import jwt_downgrader

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "jwt_downgrader"))
        await session.commit()

    seen_headers = []

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            seen_headers.append(headers or {})
            token = (headers or {}).get("Authorization", "")
            if token.endswith("."):
                return FakeHTTPResponse("accepted", status_code=200)
            return FakeHTTPResponse("rejected", status_code=401)

    monkeypatch.setattr(jwt_downgrader.httpx, "AsyncClient", FakeClient)

    result = await jwt_downgrader.test_jwt_algorithm_downgrade("https://api.local/me", make_jwt())

    assert result["vulnerable"] is True
    forged_header = result["forged_token"].split(".")[0]
    decoded_header = json.loads(base64.urlsafe_b64decode(forged_header + "=="))
    assert decoded_header["alg"] == "none"
    assert len(seen_headers) == 2
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "jwt_downgrader"))).scalars().all()
        assert len(vulns) == 1
        assert vulns[0].severity == "critical"
        assert vulns[0].vuln_type == "JWT Signature Bypass"
        await session.delete(vulns[0])
        await session.commit()


@pytest.mark.asyncio
async def test_secret_extractor_invokes_jwt_downgrade_probe(monkeypatch):
    from core import secret_extractor
    from core.models import CrawledURL

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.target_id == "target-1"))
        await session.execute(delete(CrawledURL).where(CrawledURL.id == "url-1"))
        await session.execute(delete(Target).where(Target.id == "target-1"))

        target = Target(id="target-1", name="Test Target", host="api.local")
        session.add(target)
        await session.commit()

        crawled_url = CrawledURL(id="url-1", target_id="target-1", url="https://api.local/app.js", host="api.local")
        session.add(crawled_url)
        await session.commit()

    calls = []

    async def fake_probe(origin_url, token, **kwargs):
        calls.append((origin_url, token, kwargs))
        return {"vulnerable": False}

    monkeypatch.setattr(secret_extractor, "test_jwt_algorithm_downgrade", fake_probe)

    token = make_jwt()
    try:
        findings = await secret_extractor.analyze_static_asset_for_secrets(
            f'const token = "{token}";',
            "https://api.local/app.js",
            target_id="target-1",
            crawled_url_id="url-1",
        )

        assert any(finding["type"] == "JWT" for finding in findings)
        assert calls == [("https://api.local/app.js", token, {"target_id": "target-1", "crawled_url_id": "url-1"})]
    finally:
        async with AsyncSessionLocal() as session:
            await session.execute(delete(Vulnerability).where(Vulnerability.target_id == "target-1"))
            await session.execute(delete(CrawledURL).where(CrawledURL.id == "url-1"))
            await session.execute(delete(Target).where(Target.id == "target-1"))
            await session.commit()


@pytest.mark.asyncio
async def test_bucket_hunter_flags_public_storage_listing(monkeypatch):
    from core import bucket_hunter

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "bucket_hunter"))
        target = Target(id=gen_id(), name="Buckets", host="shop2game.test")
        session.add(target)
        await session.commit()
        target_id = target.id

    monkeypatch.setattr(bucket_hunter, "generate_bucket_permutations", lambda root: ["shop2game-assets"])

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url):
            if "s3.amazonaws.com" in url:
                return FakeHTTPResponse("<ListBucketResult><Contents><Key>secret.txt</Key></Contents></ListBucketResult>")
            return FakeHTTPResponse("<Error><Code>AccessDenied</Code></Error>", status_code=403)

    monkeypatch.setattr(bucket_hunter.httpx, "AsyncClient", FakeClient)

    findings = await bucket_hunter.hunt_exposed_buckets("shop2game.test", target_id=target_id)

    assert len(findings) == 1
    assert findings[0]["provider"] == "aws-s3"
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "bucket_hunter"))).scalars().all()
        db_target = await session.get(Target, target_id)
        assert len(vulns) == 1
        assert vulns[0].target_id == target_id
        assert vulns[0].severity == "high"
        assert vulns[0].vuln_type == "Exposed Storage Bucket"
        await session.delete(vulns[0])
        await session.delete(db_target)
        await session.commit()


@pytest.mark.asyncio
async def test_stateful_idor_flags_cross_token_access(monkeypatch):
    from core import stateful_idor

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "stateful_idor"))
        await session.commit()

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            body = '{"id":1234,"owner":"user-a","plan":"enterprise"}'
            return FakeHTTPResponse(body, status_code=200, content=body.encode("utf-8"))

    monkeypatch.setattr(stateful_idor.httpx, "AsyncClient", FakeClient)

    findings = await stateful_idor.test_stateful_idor(
        ["https://api.local/api/users/1234"],
        {"Authorization": "Bearer token-a"},
        {"Authorization": "Bearer token-b"},
    )

    assert len(findings) == 1
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "stateful_idor"))).scalars().all()
        assert len(vulns) == 1
        assert vulns[0].severity == "critical"
        assert vulns[0].vuln_type == "Broken Object Level Authorization"
        await session.delete(vulns[0])
        await session.commit()


def test_offline_processor_writes_patch_analysis_for_outdated_stack(tmp_path):
    from offline_ai_processor import OfflineAIConfig, OfflineAIProcessor

    db_path = tmp_path / "telemetry.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE targets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER,
            tags TEXT,
            notes TEXT,
            tech_stack TEXT,
            risk_score REAL,
            known_cves TEXT,
            ai_triage_pending BOOLEAN NOT NULL DEFAULT 0,
            ai_summary TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE vulnerabilities (
            id TEXT PRIMARY KEY,
            vuln_type TEXT NOT NULL,
            title TEXT NOT NULL,
            created_at TEXT
        )
        """
    )
    conn.execute(
        """
        INSERT INTO targets
            (id, name, host, tech_stack, known_cves, ai_triage_pending, ai_summary, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP)
        """,
        ("target-1", "Legacy Nginx", "legacy.local", json.dumps(["Nginx 1.18.0"]), "[]", "Existing summary"),
    )
    conn.commit()
    conn.close()

    class FakeOllama:
        def __init__(self):
            self.prompts = []

        def generate(self, prompt: str) -> str:
            self.prompts.append(prompt)
            return "Nginx 1.18.0 has known request-processing risks; validate safely with version-specific probes."

    fake = FakeOllama()
    processor = OfflineAIProcessor(OfflineAIConfig(db_path=Path(db_path)), ollama=fake)

    stats = processor.run()

    assert stats["errors"] == 0
    assert len(fake.prompts) == 1
    assert "Nginx 1.18.0" in fake.prompts[0]
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    target = conn.execute("SELECT patch_analysis FROM targets WHERE id = 'target-1'").fetchone()
    conn.close()
    assert "Nginx 1.18.0" in target["patch_analysis"]
