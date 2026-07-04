"""
Stateful IDOR/BOLA traversal checks.
"""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from core.database import AsyncSessionLocal
from core.models import Vulnerability

logger = logging.getLogger("sentinel.stateful_idor")

ID_IN_PATH = re.compile(r"/(?:[^/?#]+/)*(?:\d{2,}|[0-9a-fA-F]{8,})(?:[/?#]|$)")


async def test_stateful_idor(
    endpoints: list[str],
    token_a_headers: dict[str, str],
    token_b_headers: dict[str, str],
    *,
    target_id: str | None = None,
    chained_from_vuln_id: str | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    candidate_urls = [url for url in endpoints if looks_like_object_endpoint(url)]

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
        for url in candidate_urls:
            baseline = await client.get(url, headers=token_a_headers)
            attack = await client.get(url, headers=token_b_headers)
            if is_bola_success(baseline, attack):
                finding = build_bola_finding(url, baseline, attack)
                findings.append(finding)

    if findings:
        await persist_bola_findings(findings, target_id=target_id, chained_from_vuln_id=chained_from_vuln_id)
    return findings


def looks_like_object_endpoint(url: str) -> bool:
    return bool(ID_IN_PATH.search(url))


def is_bola_success(baseline: httpx.Response, attack: httpx.Response) -> bool:
    if not (200 <= baseline.status_code < 300 and 200 <= attack.status_code < 300):
        return False
    baseline_size = len(baseline.content or b"")
    attack_size = len(attack.content or b"")
    if baseline_size == 0:
        return attack_size == 0
    return abs(baseline_size - attack_size) / baseline_size <= 0.10


def build_bola_finding(url: str, baseline: httpx.Response, attack: httpx.Response) -> dict[str, Any]:
    return {
        "url": url,
        "baseline_status": baseline.status_code,
        "attack_status": attack.status_code,
        "baseline_length": len(baseline.content or b""),
        "attack_length": len(attack.content or b""),
        "evidence": (
            f"User B token accessed User A object {url}. "
            f"Baseline status/size={baseline.status_code}/{len(baseline.content or b'')}; "
            f"cross-token status/size={attack.status_code}/{len(attack.content or b'')}."
        ),
    }


async def persist_bola_findings(
    findings: list[dict[str, Any]],
    *,
    target_id: str | None,
    chained_from_vuln_id: str | None = None,
) -> None:
    async with AsyncSessionLocal() as session:
        for finding in findings:
            session.add(
                Vulnerability(
                    target_id=target_id,
                    vuln_type="Broken Object Level Authorization",
                    severity="critical",
                    title="Cross-token object access accepted",
                    description="A second user's authorization header could access an object discovered under another user.",
                    evidence=finding["evidence"],
                    payload=finding["url"],
                    source="stateful_idor",
                    raw_data=finding,
                    chained_from_vuln_id=chained_from_vuln_id,
                )
            )
        await session.commit()
        logger.warning("Persisted %d BOLA findings", len(findings))
