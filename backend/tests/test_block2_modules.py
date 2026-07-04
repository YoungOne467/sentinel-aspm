import pytest
from sqlalchemy import delete, select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, Target, Vulnerability, gen_id


class FakeHTTPResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


@pytest.mark.asyncio
async def test_prototype_pollution_persists_browser_confirmed_finding(monkeypatch):
    from core import prototype_pollution

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "prototype_pollution"))
        target = Target(id=gen_id(), name="Proto", host="proto.local")
        session.add(target)
        await session.commit()
        target_id = target.id
        crawled = CrawledURL(id=gen_id(), target_id=target_id, host="proto.local", url="https://proto.local/app")
        session.add(crawled)
        await session.commit()

    visited_urls = []

    class FakePage:
        async def goto(self, url, wait_until=None, timeout=None):
            visited_urls.append(url)

        async def evaluate(self, expression):
            assert expression == "window.sentinel_polluted"
            return 1

        async def close(self):
            pass

    class FakeBrowser:
        async def new_page(self):
            return FakePage()

        async def close(self):
            pass

    class FakeChromium:
        async def launch(self, headless=True):
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

    class FakePlaywrightContext:
        async def __aenter__(self):
            return FakePlaywright()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(prototype_pollution, "async_playwright", lambda: FakePlaywrightContext())

    findings = await prototype_pollution.scan_prototype_pollution("https://proto.local/app")

    assert findings
    assert any("__proto__" in url for url in visited_urls)
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "prototype_pollution"))).scalars().all()
        db_target = await session.get(Target, target_id)
        assert len(vulns) == 1
        assert vulns[0].target_id == target_id
        assert vulns[0].severity == "high"
        assert vulns[0].vuln_type == "Client-Side Prototype Pollution"
        await session.delete(vulns[0])
        await session.delete(db_target)
        await session.commit()


@pytest.mark.asyncio
async def test_secret_extractor_finds_critical_tokens_and_persists():
    from core.secret_extractor import analyze_static_asset_for_secrets

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "secret_extractor"))
        target = Target(id=gen_id(), name="Secrets", host="secrets.local")
        session.add(target)
        await session.commit()
        target_id = target.id
        crawled = CrawledURL(
            id=gen_id(),
            target_id=target_id,
            host="secrets.local",
            url="https://secrets.local/app.js",
        )
        session.add(crawled)
        await session.commit()
        crawled_url_id = crawled.id

    body = """
    const aws = "AKIAIOSFODNN7EXAMPLE";
    const stripe = "sk_live_51M72ExampleSecretToken";
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
    """
    findings = await analyze_static_asset_for_secrets(
        body,
        "https://secrets.local/app.js",
        target_id=target_id,
        crawled_url_id=crawled_url_id,
    )

    assert {finding["type"] for finding in findings} >= {"AWS Access Key", "Stripe Secret Key", "JWT"}
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "secret_extractor"))).scalars().all()
        db_target = await session.get(Target, target_id)
        assert len(vulns) >= 3
        assert all(v.severity == "critical" for v in vulns)
        assert any("AKIAIOSFODNN7EXAMPLE" in v.evidence for v in vulns)
        for vuln in vulns:
            await session.delete(vuln)
        await session.delete(db_target)
        await session.commit()


@pytest.mark.asyncio
async def test_cache_poisoning_detects_poisoned_cache_hit(monkeypatch):
    from core import cache_poisoning

    async with AsyncSessionLocal() as session:
        await session.execute(delete(Vulnerability).where(Vulnerability.source == "cache_poisoning"))
        await session.commit()

    class FakeClient:
        def __init__(self, **kwargs):
            self.calls = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            self.calls += 1
            if self.calls == 1:
                return FakeHTTPResponse("normal", headers={"X-Cache": "MISS"})
            if self.calls == 2:
                return FakeHTTPResponse("sentinel-poison.local", headers={"X-Cache": "MISS"})
            return FakeHTTPResponse("sentinel-poison.local", headers={"X-Cache": "HIT"})

    monkeypatch.setattr(cache_poisoning.httpx, "AsyncClient", FakeClient)

    result = await cache_poisoning.test_cache_poisoning("https://cache.local/page")

    assert result["vulnerable"] is True
    async with AsyncSessionLocal() as session:
        vulns = (await session.execute(select(Vulnerability).where(Vulnerability.source == "cache_poisoning"))).scalars().all()
        assert len(vulns) == 1
        assert vulns[0].severity == "high"
        assert vulns[0].vuln_type == "Web Cache Poisoning"
        assert "sentinel-poison.local" in vulns[0].evidence
        await session.delete(vulns[0])
        await session.commit()
