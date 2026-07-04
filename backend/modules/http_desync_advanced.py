"""Advanced HTTP desync probes using raw socket transport."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from urllib.parse import urlparse

from core.evidence_manager import save_evidence
from core.surface_graph import build_proof_chain

logger = logging.getLogger(__name__)


def _build_raw_request(host: str, path: str, variant: str) -> bytes:
    if variant == "cl0":
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: ASPM-Desync-Probe\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"GET /aspm-desync-probe HTTP/1.1\r\nHost: {host}\r\n\r\n"
        )
    else:
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: ASPM-Desync-Probe\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "0\r\n\r\n"
            f"GET /aspm-desync-probe HTTP/1.1\r\nHost: {host}\r\n\r\n"
        )
    return request.encode("ascii", errors="ignore")


def _raw_http_probe(url: str, variant: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return {"ok": False, "error": "missing host", "response": b""}
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    request = _build_raw_request(parsed.netloc, path, variant)
    sock = socket.create_connection((host, port), timeout=8)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(8)
        sock.sendall(request)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(item) for item in chunks) > 32768:
                break
        response = b"".join(chunks)
        return {"ok": True, "variant": variant, "request": request, "response": response}
    finally:
        sock.close()


def _desync_signal(probe: dict) -> tuple[bool, list[str]]:
    response = probe.get("response") or b""
    text = response.decode("latin1", errors="ignore")
    signals = []
    if text.count("HTTP/1.") >= 2:
        signals.append("multiple_http_responses")
    if "/aspm-desync-probe" in text:
        signals.append("queued_probe_reflected")
    if "400 Bad Request" in text and "200 OK" in text:
        signals.append("split_status_codes")
    return bool(signals), signals


async def run_http_desync_advanced_scan(url, intensity, broadcast_cb, *, surface_graph=None, auth_profiles=None, scan_config=None):
    if intensity not in ["aggressive", "extreme"]:
        return []

    await broadcast_cb({"type": "log", "message": "Advanced HTTP Desync: running raw CL.0/TE.0 socket probes..."})
    findings = []
    variants = ["cl0", "te0"] if intensity == "extreme" else ["cl0"]
    for variant in variants:
        try:
            probe = await asyncio.to_thread(_raw_http_probe, url, variant)
        except Exception as exc:
            logger.debug("HTTP desync raw probe failed for %s: %s", variant, exc)
            continue
        report, signals = _desync_signal(probe)
        if not report:
            continue
        response_text = probe["response"].decode("latin1", errors="ignore")
        evidence_path = save_evidence(
            __name__,
            url,
            None,
            extra_info=f"Variant: {variant}\nSignals: {signals}\nRaw response:\n{response_text[:4000]}",
        )
        proof = build_proof_chain(
            baseline={"method": "RAW", "url": url, "identity": "scanner", "variant": variant, "status_code": None, "body_fingerprint": "raw-socket"},
            mutation={"method": "RAW", "url": url, "identity": "scanner", "variant": variant, "status_code": None, "body_fingerprint": "raw-socket"},
            verdict=", ".join(signals),
        )
        findings.append({
            "type": "Potential HTTP Desync / Request Smuggling",
            "severity": "High",
            "module": "http_desync_advanced",
            "vector": f"Raw socket {variant.upper()} probe",
            "payload": probe["request"].decode("latin1", errors="ignore")[:500],
            "evidence": evidence_path,
            "proof_chain": proof,
            "affected_identity": "scanner",
            "confidence_score": 0.78,
            "verification_state": "observed",
            "confidence": "medium",
            "description": "The raw socket probe produced response behavior consistent with HTTP parser desynchronization.",
            "remediation": "Normalize HTTP parsing at the edge, reject ambiguous CL/TE combinations, and align frontend/backend HTTP versions.",
            "patch_provided": True,
            "replay": {"method": "RAW", "url": url, "variant": variant},
        })
        await broadcast_cb({"type": "log", "message": f"  HTTP Desync signal via {variant.upper()}: {', '.join(signals)}"})
        break

    return findings
