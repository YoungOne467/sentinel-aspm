"""Failure memory for autonomous verification campaigns.

Two append-only stores are maintained:
- general_failures.jsonl: portable failure records suitable for feeding back
  into model-assisted scanner improvement.
- sites/<host>/<campaign>.jsonl: target-specific campaign memory with the
  exact timeline of failures, defenses, and the eventual success record.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


BODY_SIGNAL_PATTERNS = {
    "challenge_or_bot_defense": (
        "captcha",
        "bot check",
        "challenge",
        "verify you are human",
        "cloudflare",
        "akamai",
    ),
    "waf_or_access_block": (
        "waf",
        "mod_security",
        "request blocked",
        "access denied",
        "not acceptable",
        "forbidden",
        "malicious",
    ),
    "routing_or_endpoint_miss": (
        "not found",
        "route not found",
        "cannot get",
        "no route",
    ),
    "server_error_or_exception": (
        "traceback",
        "syntax error",
        "parse error",
        "exception",
        "stack trace",
        "internal server error",
    ),
    "reflection_without_execution": (
        "search results",
        "no results",
        "welcome",
    ),
}

HEADER_SIGNAL_PATTERNS = {
    "cloudflare": ("cf-ray", "cf-cache-status", "cloudflare"),
    "akamai": ("akamai", "akamai-ghost", "x-akamai"),
    "sucuri": ("sucuri", "x-sucuri-id", "x-sucuri-cache"),
    "imperva": ("imperva", "incap", "x-iinfo"),
    "fastly": ("fastly", "x-served-by", "x-cache"),
    "rate_limit_hint": ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: Any, limit: int | None = None) -> str:
    result = "" if value is None else str(value)
    return result[:limit] if limit else result


def _response_text(response: Any | None, fallback: str = "", limit: int = 1600) -> str:
    if response is not None:
        return _text(getattr(response, "text", fallback), limit)
    return _text(fallback, limit)


def _headers(response: Any | None) -> dict[str, str]:
    headers = getattr(response, "headers", {}) if response is not None else {}
    try:
        items = headers.items()
    except AttributeError:
        items = []
    return {str(k): _text(v, 300) for k, v in items}


def _fingerprint(value: str) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _payload_family(payload: str) -> str:
    lowered = str(payload or "").lower()
    if any(token in lowered for token in ("select", "union", "sleep", " or ", "' or", "\" or")):
        return "sql_injection"
    if any(token in lowered for token in ("<script", "onerror", "onload", "javascript:")):
        return "xss"
    if any(token in lowered for token in ("{{", "${", "<%=")):
        return "template_injection"
    if any(token in lowered for token in ("../", "..\\", "/etc/passwd", "win.ini")):
        return "file_read"
    if any(token in lowered for token in ("169.254.169.254", "127.0.0.1", "localhost", "http://", "https://")):
        return "ssrf_or_url"
    if any(token in lowered for token in ("; id", "| id", "whoami", "$(id)", "`id`")):
        return "command_injection"
    return "generic"


def _site_key(target_url: str) -> str:
    parsed = urlparse(str(target_url or ""))
    host = parsed.netloc or parsed.path or "unknown-target"
    host = host.lower().split("@")[-1]
    return re.sub(r"[^a-z0-9_.-]+", "_", host).strip("._") or "unknown-target"


def classify_defense_signals(
    status_code: int | str | None,
    *,
    response: Any | None = None,
    response_text: str = "",
    headers: dict[str, Any] | None = None,
) -> list[str]:
    signals: list[str] = []
    try:
        status = int(status_code or 0)
    except (TypeError, ValueError):
        status = 0

    if status in (401, 403, 406, 418, 451):
        signals.append("waf_or_access_block")
    if status == 404:
        signals.append("routing_or_endpoint_miss")
    if status == 429:
        signals.extend(["rate_limited", "rate_limit_hint"])
    if status >= 500:
        signals.append("server_error_or_exception")
    if status == 0:
        signals.append("network_drop_or_timeout")

    body = (_response_text(response, response_text) or response_text or "").lower()
    header_values = {str(k).lower(): str(v).lower() for k, v in (_headers(response) | (headers or {})).items()}
    header_blob = " ".join([*header_values.keys(), *header_values.values()])

    for signal, tokens in BODY_SIGNAL_PATTERNS.items():
        if any(token in body for token in tokens):
            signals.append(signal)
    for signal, tokens in HEADER_SIGNAL_PATTERNS.items():
        if any(token in header_blob for token in tokens):
            signals.append(signal)

    return list(dict.fromkeys(signals or ["no_specific_defense_signal"]))


class FailureMemoryStore:
    def __init__(self, base_dir: str | os.PathLike[str] | None = None):
        self.base_dir = Path(base_dir or Path(os.getcwd()) / "scratch" / "failure_memory")
        self.general_path = self.base_dir / "general_failures.jsonl"
        self.sites_dir = self.base_dir / "sites"

    def _ensure_dirs(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.sites_dir.mkdir(parents=True, exist_ok=True)

    def _site_campaign_path(self, target_url: str, campaign_id: str) -> Path:
        site_dir = self.sites_dir / _site_key(target_url)
        site_dir.mkdir(parents=True, exist_ok=True)
        safe_campaign = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(campaign_id or "default")).strip("._") or "default"
        return site_dir / f"{safe_campaign}.jsonl"

    def _append_jsonl(self, path: Path, record: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def record_failure(
        self,
        *,
        campaign_id: str,
        target_url: str,
        vuln_type: str,
        vector: str,
        payload: str,
        status_code: int | str | None,
        response: Any | None = None,
        response_text: str = "",
        attempt_no: int | None = None,
        ai_feedback: str | None = None,
        generated_mutations: list[str] | None = None,
        request_metadata: dict[str, Any] | None = None,
        phase: str = "verification",
    ) -> dict[str, str]:
        self._ensure_dirs()
        body_excerpt = _response_text(response, response_text)
        response_headers = _headers(response)
        signals = classify_defense_signals(status_code, response=response, response_text=body_excerpt)
        payload_text = _text(payload, 4000)
        common = {
            "timestamp": _now(),
            "campaign_id": campaign_id,
            "phase": phase,
            "vuln_type": str(vuln_type or "").lower(),
            "vector": _text(vector, 500),
            "payload": payload_text,
            "payload_family": _payload_family(payload_text),
            "payload_fingerprint": _fingerprint(payload_text),
            "status_code": str(status_code),
            "defense_signals": signals,
            "response_fingerprint": _fingerprint(body_excerpt),
            "response_excerpt": body_excerpt,
            "ai_feedback": _text(ai_feedback, 2000),
            "generated_mutations": list(generated_mutations or [])[:10],
            "attempt_no": attempt_no,
        }
        general_record = {
            **common,
            "record_type": "general_failure",
            "site_key": _site_key(target_url),
            "response_headers_observed": {
                key: response_headers[key]
                for key in sorted(response_headers)
                if key.lower() in {"server", "x-powered-by", "via", "cf-ray", "retry-after", "x-cache"}
            },
            "ai_prompt_context": (
                f"{vuln_type} failed with HTTP {status_code}; "
                f"signals={', '.join(signals)}; vector={vector}; family={_payload_family(payload_text)}"
            ),
        }
        site_record = {
            **common,
            "record_type": "site_failure",
            "target_url": target_url,
            "site_key": _site_key(target_url),
            "request": request_metadata or {},
            "response_headers": response_headers,
        }

        site_path = self._site_campaign_path(target_url, campaign_id)
        self._append_jsonl(self.general_path, general_record)
        self._append_jsonl(site_path, site_record)
        return {"general_path": str(self.general_path), "site_path": str(site_path)}

    def record_success(
        self,
        *,
        campaign_id: str,
        target_url: str,
        vuln_type: str,
        vector: str,
        payload: str,
        status_code: int | str | None,
        attempts: int,
        response: Any | None = None,
        evidence: Any | None = None,
        request_metadata: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        self._ensure_dirs()
        body_excerpt = _response_text(response, limit=1600)
        record = {
            "timestamp": _now(),
            "record_type": "site_success",
            "campaign_id": campaign_id,
            "target_url": target_url,
            "site_key": _site_key(target_url),
            "vuln_type": str(vuln_type or "").lower(),
            "vector": _text(vector, 500),
            "payload": _text(payload, 4000),
            "payload_family": _payload_family(payload),
            "payload_fingerprint": _fingerprint(_text(payload, 4000)),
            "status_code": str(status_code),
            "attempts": attempts,
            "response_fingerprint": _fingerprint(body_excerpt),
            "response_excerpt": body_excerpt,
            "request": request_metadata or {},
            "evidence_summary": evidence.get("summary") if isinstance(evidence, dict) else _text(evidence, 500),
        }
        site_path = self._site_campaign_path(target_url, campaign_id)
        self._append_jsonl(site_path, record)
        return {"site_path": str(site_path)}

    def load_site_memory(self, target_url: str, campaign_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        site_dir = self.sites_dir / _site_key(target_url)
        if not site_dir.exists():
            return []
        paths = [self._site_campaign_path(target_url, campaign_id)] if campaign_id else sorted(site_dir.glob("*.jsonl"))
        records: list[dict[str, Any]] = []
        for path in paths:
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records[-limit:]

    def load_general_failures(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.general_path.exists():
            return []
        records = []
        for line in self.general_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records[-limit:]

    def summarize_site_memory(
        self,
        target_url: str,
        *,
        campaign_id: str | None = None,
        vuln_type: str | None = None,
        limit: int = 80,
    ) -> dict[str, Any]:
        records = self.load_site_memory(target_url, campaign_id=campaign_id, limit=limit)
        if vuln_type:
            vt = vuln_type.lower()
            records = [record for record in records if str(record.get("vuln_type", "")).lower() == vt]

        failures = [record for record in records if record.get("record_type") == "site_failure"]
        successes = [record for record in records if record.get("record_type") == "site_success"]
        defense_signals = []
        failed_payloads = []
        ai_feedback = []
        for failure in failures:
            defense_signals.extend(failure.get("defense_signals") or [])
            failed_payloads.append(failure.get("payload"))
            if failure.get("ai_feedback"):
                ai_feedback.append(failure["ai_feedback"])

        latest_success = successes[-1] if successes else None
        return {
            "site_key": _site_key(target_url),
            "campaign_id": campaign_id,
            "record_count": len(records),
            "failure_count": len(failures),
            "succeeded": bool(latest_success),
            "success_payload": latest_success.get("payload") if latest_success else None,
            "defense_signals": list(dict.fromkeys(defense_signals)),
            "failed_payloads": [payload for payload in failed_payloads if payload][-20:],
            "recent_ai_feedback": ai_feedback[-10:],
        }
