"""
Subdomain takeover profiler.

Resolves discovered subdomain CNAMEs and flags dangling cloud-provider
signatures when the target responds as unclaimed.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import httpx

from core.database import AsyncSessionLocal
from core.models import Vulnerability

logger = logging.getLogger("sentinel.takeover_profiler")

TAKEOVER_SIGNATURES = {
    "GitHub Pages": ("github.io", "github.map.fastly.net"),
    "AWS S3": ("s3.amazonaws.com", "s3-website"),
    "Azure": ("azurewebsites.net", "cloudapp.net", "trafficmanager.net"),
    "Heroku": ("herokuapp.com", "herokudns.com"),
    "Fastly": ("fastly.net",),
    "Shopify": ("myshopify.com",),
    "Unbounce": ("unbouncepages.com",),
}
UNCLAIMED_STATUS_CODES = {0, 404, 410}


async def profile_subdomain_takeover(subdomain: str, target_id: str | None = None) -> dict[str, Any]:
    cname = await resolve_cname(subdomain)
    provider = match_takeover_provider(cname or "")
    if not provider:
        return {"subdomain": subdomain, "cname": cname, "vulnerable": False, "provider": None}

    status_code = await probe_http_status(f"https://{subdomain}")
    vulnerable = status_code in UNCLAIMED_STATUS_CODES
    result = {
        "subdomain": subdomain,
        "cname": cname,
        "provider": provider,
        "status_code": status_code,
        "vulnerable": vulnerable,
    }
    if vulnerable:
        await persist_takeover_finding(result, target_id)
    return result


async def resolve_cname(subdomain: str) -> str | None:
    try:
        import dns.resolver  # type: ignore

        answers = await asyncio.to_thread(dns.resolver.resolve, subdomain, "CNAME")
        for answer in answers:
            return str(answer.target).rstrip(".")
    except Exception:
        pass

    try:
        _host, aliases, _addresses = await asyncio.to_thread(socket.gethostbyname_ex, subdomain)
        return aliases[0].rstrip(".") if aliases else None
    except Exception as exc:
        logger.debug("CNAME resolution failed for %s: %s", subdomain, exc)
        return None


def match_takeover_provider(cname: str) -> str | None:
    lower = cname.lower().rstrip(".")
    for provider, signatures in TAKEOVER_SIGNATURES.items():
        if any(signature in lower for signature in signatures):
            return provider
    return None


async def probe_http_status(url: str) -> int:
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            response = await client.get(url)
            return response.status_code
    except Exception:
        return 0


async def persist_takeover_finding(result: dict[str, Any], target_id: str | None) -> None:
    evidence = (
        f"Subdomain {result['subdomain']} has CNAME {result['cname']} matching "
        f"{result['provider']} and returned status {result['status_code']}, suggesting an unclaimed resource."
    )
    async with AsyncSessionLocal() as session:
        session.add(
            Vulnerability(
                target_id=target_id,
                vuln_type="Subdomain Takeover",
                severity="high",
                title=f"Potential subdomain takeover: {result['subdomain']}",
                description="A discovered subdomain points at a cloud provider takeover signature and appears unclaimed.",
                evidence=evidence,
                source="takeover_profiler",
                raw_data=result,
            )
        )
        await session.commit()
