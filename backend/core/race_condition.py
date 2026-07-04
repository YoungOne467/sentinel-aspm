"""
HTTP/2 single-packet style race condition probe.

This engine sends a burst of identical requests over one HTTP/2-capable client
and records high-severity anomalies when identical state-changing operations
produce mixed success/rejection outcomes.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections import Counter
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, Vulnerability

logger = logging.getLogger("sentinel.race_condition")

REQUEST_COUNT = 20
REQUEST_TIMEOUT = 30.0


@dataclass(frozen=True)
class RaceResponseSample:
    index: int
    status_code: int | None
    body_hash: str | None
    body_length: int
    error: str | None = None


async def test_race_condition(
    url: str,
    method: str,
    headers: dict,
    data: dict,
) -> dict[str, Any]:
    """
    Dispatch 20 identical HTTP requests over HTTP/2 and persist race anomalies.

    Returns a compact result dictionary for callers that want to display or
    route the finding without querying the database.
    """
    normalized_method = method.upper()
    request_kwargs = {
        "headers": dict(headers or {}),
        "json": dict(data or {}),
    }

    async with httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        follow_redirects=False,
    ) as client:
        tasks = [
            client.request(normalized_method, url, **request_kwargs)
            for _ in range(REQUEST_COUNT)
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    samples = [_sample_response(index, result) for index, result in enumerate(raw_results)]
    analysis = analyze_race_samples(samples)

    result: dict[str, Any] = {
        "url": url,
        "method": normalized_method,
        "request_count": REQUEST_COUNT,
        "anomaly_detected": analysis["anomaly_detected"],
        "severity": "high" if analysis["anomaly_detected"] else None,
        "status_counts": analysis["status_counts"],
        "success_count": analysis["success_count"],
        "error_count": analysis["error_count"],
        "evidence": analysis["evidence"],
    }

    if analysis["anomaly_detected"]:
        vulnerability_id = await persist_race_condition(url, normalized_method, data or {}, analysis)
        result["vulnerability_id"] = vulnerability_id

    return result


def _sample_response(index: int, result: httpx.Response | BaseException) -> RaceResponseSample:
    if isinstance(result, BaseException):
        return RaceResponseSample(
            index=index,
            status_code=None,
            body_hash=None,
            body_length=0,
            error=f"{type(result).__name__}: {result}",
        )

    text = result.text or ""
    return RaceResponseSample(
        index=index,
        status_code=result.status_code,
        body_hash=hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16],
        body_length=len(text),
    )


def analyze_race_samples(samples: list[RaceResponseSample]) -> dict[str, Any]:
    status_counts = Counter(sample.status_code for sample in samples if sample.status_code is not None)
    error_count = sum(1 for sample in samples if sample.error)
    success_count = sum(1 for sample in samples if sample.status_code is not None and 200 <= sample.status_code < 300)
    rejection_count = sum(
        1
        for sample in samples
        if sample.status_code is not None and sample.status_code >= 400
    )
    unique_success_hashes = {
        sample.body_hash
        for sample in samples
        if sample.status_code is not None and 200 <= sample.status_code < 300
    }

    mixed_success_rejection = success_count > 0 and rejection_count > 0
    divergent_success_bodies = success_count > 1 and len(unique_success_hashes) > 1
    partial_transport_failure = success_count > 0 and error_count > 0
    anomaly_detected = mixed_success_rejection or divergent_success_bodies or partial_transport_failure

    evidence = (
        f"HTTP/2 race probe sent {len(samples)} identical requests. "
        f"Observed {success_count} successful responses, {rejection_count} rejection/error status responses, "
        f"and {error_count} transport errors. Status distribution: {dict(status_counts)}."
    )
    if divergent_success_bodies:
        evidence += f" Successful response bodies diverged across {len(unique_success_hashes)} hashes."

    return {
        "anomaly_detected": anomaly_detected,
        "status_counts": dict(status_counts),
        "success_count": success_count,
        "rejection_count": rejection_count,
        "error_count": error_count,
        "evidence": evidence,
        "samples": [
            {
                "index": sample.index,
                "status_code": sample.status_code,
                "body_hash": sample.body_hash,
                "body_length": sample.body_length,
                "error": sample.error,
            }
            for sample in samples
        ],
    }


async def persist_race_condition(
    url: str,
    method: str,
    data: dict,
    analysis: dict[str, Any],
) -> str:
    async with AsyncSessionLocal() as session:
        crawled_url_result = await session.execute(select(CrawledURL).where(CrawledURL.url == url))
        crawled_url = crawled_url_result.scalars().first()
        vulnerability = Vulnerability(
            crawled_url_id=crawled_url.id if crawled_url else None,
            target_id=crawled_url.target_id if crawled_url else None,
            vuln_type="Race Condition",
            severity="high",
            title="Potential HTTP/2 single-packet race condition",
            description=(
                "Concurrent identical HTTP/2 requests produced inconsistent state-change responses, "
                "indicating the endpoint may not serialize a sensitive operation."
            ),
            evidence=analysis["evidence"],
            payload=json.dumps({"method": method, "url": url, "data": data}, ensure_ascii=False),
            source="race_condition_engine",
            raw_data={
                "method": method,
                "url": url,
                "request_count": REQUEST_COUNT,
                "status_counts": analysis["status_counts"],
                "success_count": analysis["success_count"],
                "rejection_count": analysis["rejection_count"],
                "error_count": analysis["error_count"],
                "samples": analysis["samples"],
            },
        )
        session.add(vulnerability)
        await session.commit()
        await session.refresh(vulnerability)
        logger.warning("Persisted high-severity race condition finding for %s", url)
        return vulnerability.id
