"""
Cloud bucket misconfiguration hunter.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from core.database import AsyncSessionLocal
from core.models import Vulnerability

logger = logging.getLogger("sentinel.bucket_hunter")

COMMON_BUCKET_SUFFIXES = (
    "",
    "dev",
    "prod",
    "production",
    "stage",
    "staging",
    "test",
    "qa",
    "assets",
    "static",
    "media",
    "uploads",
    "files",
    "backup",
    "backups",
    "logs",
    "public",
    "private",
    "cdn",
    "images",
    "img",
    "docs",
    "data",
    "web",
    "app",
)


async def hunt_exposed_buckets(root_domain: str, *, target_id: str | None = None) -> list[dict[str, Any]]:
    buckets = generate_bucket_permutations(root_domain)
    findings: list[dict[str, Any]] = []
    semaphore = asyncio.Semaphore(10)

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        tasks = [
            probe_bucket_endpoint(client, semaphore, "aws-s3", bucket, f"https://{bucket}.s3.amazonaws.com")
            for bucket in buckets
        ]
        tasks.extend(
            probe_bucket_endpoint(client, semaphore, "azure-blob", bucket, f"https://{bucket}.blob.core.windows.net")
            for bucket in buckets
        )
        for result in await asyncio.gather(*tasks):
            if result:
                findings.append(result)

    if findings:
        await persist_bucket_findings(findings, target_id=target_id)
    return findings


def generate_bucket_permutations(root_domain: str) -> list[str]:
    root = root_domain.split(".")[0].lower()
    root = re.sub(r"[^a-z0-9-]", "-", root).strip("-")
    if not root:
        return []

    candidates: list[str] = []
    for suffix in COMMON_BUCKET_SUFFIXES:
        candidates.append(root if not suffix else f"{root}-{suffix}")
        if suffix:
            candidates.append(f"{suffix}-{root}")
        if len(candidates) >= 50:
            break
    return list(dict.fromkeys(candidates))[:50]


async def probe_bucket_endpoint(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    provider: str,
    bucket: str,
    url: str,
) -> dict[str, Any] | None:
    async with semaphore:
        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            logger.debug("Bucket probe failed for %s: %s", url, exc)
            return None

    if is_public_listing(response.text):
        return {
            "provider": provider,
            "bucket": bucket,
            "url": url,
            "status_code": response.status_code,
            "evidence": response.text[:1000],
        }
    return None


def is_public_listing(text: str) -> bool:
    lowered = (text or "").lower()
    if "accessdenied" in lowered or "nosuchbucket" in lowered or "authenticationfailed" in lowered:
        return False
    return (
        "<listbucketresult" in lowered and "<contents>" in lowered
    ) or (
        "<enumerationresults" in lowered and "<blob>" in lowered
    )


async def persist_bucket_findings(findings: list[dict[str, Any]], *, target_id: str | None) -> None:
    async with AsyncSessionLocal() as session:
        for finding in findings:
            evidence = (
                f"{finding['provider']} bucket listing exposed at {finding['url']}. "
                f"Response snippet: {finding['evidence'][:300]}"
            )
            session.add(
                Vulnerability(
                    target_id=target_id,
                    vuln_type="Exposed Storage Bucket",
                    severity="high",
                    title="Public cloud storage bucket listing",
                    description="A guessed cloud storage bucket returned an object listing instead of AccessDenied.",
                    evidence=evidence,
                    payload=finding["url"],
                    source="bucket_hunter",
                    raw_data=finding,
                )
            )
        await session.commit()
        logger.warning("Persisted %d exposed bucket findings", len(findings))
