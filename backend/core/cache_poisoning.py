"""
Web cache poisoning probes.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, Vulnerability

logger = logging.getLogger("sentinel.cache_poisoning")

POISON_HOST = "sentinel-poison.local"
POISON_HEADERS = {
    "X-Forwarded-Host": POISON_HOST,
    "X-Original-URL": "/sentinel-poison",
    "X-Rewrite-URL": "/sentinel-poison",
}


async def test_cache_poisoning(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
        baseline = await client.get(url)
        poisoned = await client.get(url, headers=POISON_HEADERS)
        validation = await client.get(url)

    poisoned_reflected = POISON_HOST in (poisoned.text or "")
    validation_reflected = POISON_HOST in (validation.text or "")
    cache_hit = "hit" in validation.headers.get("X-Cache", "").lower()
    vulnerable = validation_reflected or (cache_hit and (poisoned_reflected or validation_reflected))

    result = {
        "url": url,
        "vulnerable": vulnerable,
        "baseline_status": baseline.status_code,
        "poisoned_status": poisoned.status_code,
        "validation_status": validation.status_code,
        "poisoned_reflected": poisoned_reflected,
        "validation_reflected": validation_reflected,
        "validation_x_cache": validation.headers.get("X-Cache", ""),
    }
    if vulnerable:
        await persist_cache_poisoning(result)
    return result


async def persist_cache_poisoning(result: dict[str, Any]) -> None:
    async with AsyncSessionLocal() as session:
        crawled_url_result = await session.execute(select(CrawledURL).where(CrawledURL.url == result["url"]))
        crawled_url = crawled_url_result.scalars().first()
        evidence = (
            f"Injected {POISON_HOST} via unkeyed cache headers. "
            f"Validation response reflected poison={result['validation_reflected']} "
            f"with X-Cache={result['validation_x_cache']!r}."
        )
        session.add(
            Vulnerability(
                crawled_url_id=crawled_url.id if crawled_url else None,
                target_id=crawled_url.target_id if crawled_url else None,
                vuln_type="Web Cache Poisoning",
                severity="high",
                title="Potential web cache poisoning",
                description="A poisoned cache header appeared to influence a later normal response.",
                evidence=evidence,
                payload=str(POISON_HEADERS),
                source="cache_poisoning",
                raw_data=result,
            )
        )
        await session.commit()
