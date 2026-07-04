import pytest
import os
import json
from datetime import datetime, timezone
from sqlalchemy import select, update
from core.database import AsyncSessionLocal, init_db
from core.models import Target, Finding, CrawledURL, gen_id
from core.url_parser import ingest_katana_urls, extract_host_from_url
from core.pipeline_manager import run_pipeline

@pytest.mark.asyncio
async def test_extract_host_from_url():
    assert extract_host_from_url("http://sub.domain.com/path?query=1") == "sub.domain.com"
    assert extract_host_from_url("https://another.sub.domain.com:8080/another/path") == "another.sub.domain.com:8080"
    assert extract_host_from_url("invalid-url") == "invalid-url"

from unittest.mock import patch, AsyncMock

@pytest.mark.asyncio
async def test_ingest_katana_urls():
    with patch("core.dlp_parser.analyze_url_telemetry", new_callable=AsyncMock) as mock_analyze:
        # Setup test target
        async with AsyncSessionLocal() as session:
            target = Target(
                id=gen_id(),
                name="Katana Test Target",
                host="katana.local",
                port=80
            )
            session.add(target)
            await session.commit()
            target_id = target.id

        # Test Katana parsing
        raw_output = (
            '{"request": {"url": "http://katana.local/api/v1/users"}}\n'
            '{"url": "https://sub.katana.local/about"}\n'
            'invalid line to be skipped\n'
            'http://katana.local/fallback-url\n'
        )

        new_urls_count = await ingest_katana_urls(target_id, None, raw_output)
        assert new_urls_count == 3

        # Check database
        async with AsyncSessionLocal() as session:
            urls_res = await session.execute(
                select(CrawledURL).where(CrawledURL.target_id == target_id)
            )
            urls = urls_res.scalars().all()
            assert len(urls) == 3
            
            # Check Netloc Host extraction
            c_api = next(u for u in urls if "/api/v1/users" in u.url)
            assert c_api.host == "katana.local"
            assert c_api.is_new is True

            c_sub = next(u for u in urls if "sub.katana.local" in u.url)
            assert c_sub.host == "sub.katana.local"

            c_fallback = next(u for u in urls if "/fallback-url" in u.url)
            assert c_fallback.host == "katana.local"

        # Test URL Diffing Engine: Ingest same URLs again
        new_urls_count_2 = await ingest_katana_urls(target_id, None, raw_output)
        assert new_urls_count_2 == 0 # no new URLs added

        async with AsyncSessionLocal() as session:
            urls_res = await session.execute(
                select(CrawledURL).where(CrawledURL.target_id == target_id)
            )
            urls = urls_res.scalars().all()
            assert len(urls) == 3
            # Verify is_new was set to False upon re-ingestion/exist match
            for u in urls:
                assert u.is_new is False

        # Cleanup target
        async with AsyncSessionLocal() as session:
            t = await session.get(Target, target_id)
            await session.delete(t)
            await session.commit()

