"""
Client-side prototype pollution probe using Playwright.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, Vulnerability

try:
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover - exercised only when Playwright is absent
    async_playwright = None

logger = logging.getLogger("sentinel.prototype_pollution")

POLLUTION_PAYLOADS = (
    ("__proto__[sentinel_polluted]", "1"),
    ("constructor[prototype][sentinel_polluted]", "1"),
)


def build_pollution_urls(url: str) -> list[str]:
    parts = urlsplit(url)
    poisoned: list[str] = []
    existing = parse_qsl(parts.query, keep_blank_values=True)
    for key, value in POLLUTION_PAYLOADS:
        query = urlencode(existing + [(key, value)])
        poisoned.append(urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment)))
        fragment = urlencode([(key, value)])
        poisoned.append(urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, fragment)))
    return list(dict.fromkeys(poisoned))


async def scan_prototype_pollution(url: str) -> list[dict[str, Any]]:
    if async_playwright is None:
        logger.warning("Playwright is not installed; skipping prototype pollution scan")
        return []

    findings: list[dict[str, Any]] = []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            for poisoned_url in build_pollution_urls(url):
                page = await browser.new_page()
                try:
                    await page.goto(poisoned_url, wait_until="networkidle", timeout=15000)
                    polluted = await page.evaluate("window.sentinel_polluted")
                finally:
                    await page.close()
                if polluted is True or polluted == 1 or polluted == "1":
                    finding = build_finding(url, poisoned_url, polluted)
                    findings.append(finding)
                    await persist_prototype_pollution(finding)
                    break
        finally:
            await browser.close()
    return findings


def build_finding(base_url: str, poisoned_url: str, polluted_value: Any) -> dict[str, Any]:
    return {
        "type": "Client-Side Prototype Pollution",
        "severity": "high",
        "title": "Client-side prototype pollution confirmed",
        "description": "A poisoned URL parameter or fragment modified the JavaScript runtime prototype state.",
        "url": base_url,
        "poisoned_url": poisoned_url,
        "payload": poisoned_url,
        "evidence": f"Loading {poisoned_url} caused window.sentinel_polluted to evaluate to {polluted_value!r}.",
        "source": "prototype_pollution",
    }


async def persist_prototype_pollution(finding: dict[str, Any]) -> None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(CrawledURL).where(CrawledURL.url == finding["url"]))
        crawled_url = result.scalars().first()
        session.add(
            Vulnerability(
                crawled_url_id=crawled_url.id if crawled_url else None,
                target_id=crawled_url.target_id if crawled_url else None,
                vuln_type=finding["type"],
                severity=finding["severity"],
                title=finding["title"],
                description=finding["description"],
                evidence=finding["evidence"],
                payload=finding["payload"],
                source=finding["source"],
                raw_data=finding,
            )
        )
        await session.commit()
