"""
Remote OOB canary tracking for blind SSRF and blind XSS.

The tracker does not run a local listener. It creates correlation domains,
stores them in SQLite, and periodically polls a remote Interactsh-compatible
API for delayed DNS/HTTP interactions.
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import httpx
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, OOBCanary, Vulnerability, gen_id
from core.oast_listener import get_oast_settings

logger = logging.getLogger("sentinel.oob_tracker")

OOB_HEADERS = ("X-Forwarded-For", "X-Real-IP", "Referer", "Contact")
DEFAULT_BASE_DOMAIN = "oob.invalid"
DEFAULT_TIMEOUT = 20.0


async def generate_canary_payload(
    target_url: str,
    parameter: str = "headers",
    *,
    target_id: str | None = None,
    crawled_url_id: str | None = None,
) -> str:
    correlation_id = uuid.uuid4().hex
    canary_domain = await request_oob_domain(correlation_id)
    oast_settings = get_oast_settings()

    async with AsyncSessionLocal() as session:
        if crawled_url_id is None or target_id is None:
            result = await session.execute(select(CrawledURL).where(CrawledURL.url == target_url))
            crawled_url = result.scalars().first()
            if crawled_url:
                crawled_url_id = crawled_url_id or crawled_url.id
                target_id = target_id or crawled_url.target_id

        session.add(
            OOBCanary(
                id=gen_id(),
                correlation_id=correlation_id,
                canary_domain=canary_domain,
                target_url=target_url,
                parameter=parameter,
                target_id=target_id,
                crawled_url_id=crawled_url_id,
                provider=os.getenv("OOB_PROVIDER", "interactsh"),
                oast_domain=oast_settings.get("domain"),
                oast_private=bool(oast_settings.get("private")),
                oast_auth_configured=bool(oast_settings.get("token_configured")),
                status="pending",
            )
        )
        await session.commit()

    return canary_domain


async def request_oob_domain(correlation_id: str) -> str:
    settings = get_oast_settings(include_token=True)
    register_url = os.getenv("OOB_REGISTER_URL", "").strip() or str(settings.get("register_url") or "").strip()
    base_domain = (os.getenv("OOB_BASE_DOMAIN", "").strip() or str(settings.get("domain") or DEFAULT_BASE_DOMAIN)).strip(".")
    fallback_domain = f"{correlation_id}.{base_domain}"

    if not register_url or not settings.get("private"):
        return fallback_domain

    token = str(settings.get("token") or "") or os.getenv("OOB_POLL_TOKEN") or os.getenv("INTERACTSH_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.post(register_url, json={"correlation_id": correlation_id}, headers=headers)
            response.raise_for_status()
            body = response.json()
        return (
            body.get("domain")
            or body.get("canary_domain")
            or body.get("url")
            or fallback_domain
        )
    except Exception as exc:
        logger.warning("OOB registration failed, using derived domain: %s", exc)
        return fallback_domain


async def generate_oob_headers(target_url: str, *, target_id: str | None = None, crawled_url_id: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for header in OOB_HEADERS:
        headers[header] = await generate_canary_payload(
            target_url,
            header,
            target_id=target_id,
            crawled_url_id=crawled_url_id,
        )
    return headers


async def poll_remote_oob_server(
    broadcast_cb: Callable[[dict], Awaitable[None]] | None = None,
) -> dict[str, int]:
    settings = get_oast_settings(include_token=True)
    poll_url = os.getenv("OOB_POLL_URL", "").strip() or str(settings.get("poll_url") or "").strip()
    if not poll_url:
        return {"interactions": 0, "matched": 0, "created": 0}

    token = str(settings.get("token") or "") or os.getenv("OOB_POLL_TOKEN") or os.getenv("INTERACTSH_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        response = await client.get(poll_url, headers=headers)
        response.raise_for_status()
        payload = response.json()

    interactions = normalize_interactions(payload)
    created = 0
    matched = 0

    async with AsyncSessionLocal() as session:
        for interaction in interactions:
            correlation_id = extract_correlation_id(interaction)
            if not correlation_id:
                continue
            result = await session.execute(select(OOBCanary).where(OOBCanary.correlation_id == correlation_id))
            canary = result.scalars().first()
            if not canary:
                continue
            matched += 1
            existing_interactions = list(canary.raw_interactions or [])
            existing_interactions.append(interaction)
            canary.raw_interactions = existing_interactions
            canary.interaction_count = len(existing_interactions)
            canary.last_polled_at = datetime.now(timezone.utc).replace(tzinfo=None)

            if canary.status != "triggered":
                canary.status = "triggered"
                canary.triggered_at = datetime.now(timezone.utc).replace(tzinfo=None)
                session.add(build_oob_vulnerability(canary, interaction))
                created += 1

        await session.commit()

    if created and broadcast_cb:
        await broadcast_cb({
            "type": "system_alert",
            "message": f"OOB tracker confirmed {created} asynchronous SSRF/Blind XSS interaction(s).",
        })

    return {"interactions": len(interactions), "matched": matched, "created": created}


def normalize_interactions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("interactions"), list):
        return [dict(item) for item in payload["interactions"] if isinstance(item, dict)]
    if isinstance(payload.get("data"), list):
        return [dict(item) for item in payload["data"] if isinstance(item, dict)]
    if isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("interactions"), list):
        return [dict(item) for item in payload["data"]["interactions"] if isinstance(item, dict)]
    return []


def extract_correlation_id(interaction: dict[str, Any]) -> str | None:
    for key in ("correlation_id", "correlationId", "id", "unique_id", "full-id"):
        value = interaction.get(key)
        if value:
            return str(value).split(".")[0]
    haystack = " ".join(str(interaction.get(key, "")) for key in ("raw_request", "request", "domain", "full_id", "full-id"))
    match = re.search(r"\b([a-f0-9]{16,32})\.", haystack, re.IGNORECASE)
    return match.group(1) if match else None


def build_oob_vulnerability(canary: OOBCanary, interaction: dict[str, Any]) -> Vulnerability:
    protocol = interaction.get("protocol") or interaction.get("type") or "oob"
    remote = interaction.get("remote_address") or interaction.get("remoteAddress") or interaction.get("ip") or "unknown"
    evidence = (
        f"Remote OOB interaction received for canary {canary.canary_domain}. "
        f"Target URL: {canary.target_url}. Parameter/header: {canary.parameter}. "
        f"Protocol: {protocol}. Remote peer: {remote}."
    )
    return Vulnerability(
        crawled_url_id=canary.crawled_url_id,
        target_id=canary.target_id,
        vuln_type="SSRF/Blind XSS",
        severity="high",
        title="Asynchronous OOB interaction confirmed",
        description=(
            "A delayed DNS/HTTP callback was observed for an injected canary, "
            "indicating a blind SSRF, blind XSS, or backend fetch primitive."
        ),
        evidence=evidence,
        payload=canary.canary_domain,
        source="oob_tracker",
        raw_data={"canary_id": canary.id, "interaction": interaction},
    )


class OOBPoller:
    def __init__(self, interval_seconds: float = 60.0, broadcast_cb: Callable[[dict], Awaitable[None]] | None = None):
        self.interval_seconds = interval_seconds
        self.broadcast_cb = broadcast_cb
        self._running = False

    async def start(self) -> None:
        self._running = True
        while self._running:
            try:
                await poll_remote_oob_server(self.broadcast_cb)
            except Exception as exc:
                logger.warning("OOB poll failed: %s", exc)
            await _sleep(self.interval_seconds)

    async def stop(self) -> None:
        self._running = False


async def _sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)
