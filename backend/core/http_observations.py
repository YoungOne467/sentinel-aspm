"""HTTP response observation helpers shared by advanced scanner modules.

These helpers give modules a common way to compare baseline and variant
responses. The goal is to report findings from differential evidence instead
of one-off string matches.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


CACHE_STATUS_HEADERS = (
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "cache-status",
    "x-served-by",
)


def _headers_dict(response: Any) -> dict[str, str]:
    headers = getattr(response, "headers", {}) or {}
    return {str(name).lower(): str(value) for name, value in dict(headers).items()}


def header_value(response: Any, name: str, default: str = "") -> str:
    """Return a response header using case-insensitive lookup."""
    return _headers_dict(response).get(name.lower(), default)


def _body_text(response: Any, limit: int = 8192) -> str:
    if response is None:
        return ""
    if hasattr(response, "text"):
        try:
            return str(response.text)[:limit]
        except Exception:
            return ""
    content = getattr(response, "content", b"") or b""
    if isinstance(content, bytes):
        return content[:limit].decode("utf-8", errors="ignore")
    return str(content)[:limit]


def fingerprint_response(response: Any) -> dict[str, Any]:
    """Build a stable, compact fingerprint for response comparison."""
    body = _body_text(response)
    headers = _headers_dict(response)
    header_text = "\n".join(f"{name}: {value}" for name, value in sorted(headers.items()))
    return {
        "status_code": int(getattr(response, "status_code", 0) or 0),
        "headers": headers,
        "header_text": header_text,
        "body_len": len(body),
        "body_hash": hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest(),
        "body_sample": body,
        "content_type": headers.get("content-type", ""),
        "location": headers.get("location", ""),
        "cache_control": headers.get("cache-control", ""),
        "vary": headers.get("vary", ""),
        "etag": headers.get("etag", ""),
        "last_modified": headers.get("last-modified", ""),
        "age": headers.get("age", ""),
    }


def _vary_tokens(vary: str) -> set[str]:
    return {token.strip().lower() for token in re.split(r",\s*", vary or "") if token.strip()}


def cache_indicators(response: Any, varied_header: str | None = None) -> dict[str, Any]:
    """Score whether a response looks cacheable and whether a tested header is keyed."""
    headers = _headers_dict(response)
    cache_control = headers.get("cache-control", "").lower()
    signals: list[str] = []
    score = 0

    if "no-store" in cache_control:
        signals.append("explicit_no_store")
        score -= 3
    if "private" in cache_control:
        signals.append("explicit_private_cache_control")
        score -= 2
    if "public" in cache_control:
        signals.append("explicit_public_cache_control")
        score += 2
    if "s-maxage" in cache_control or re.search(r"\bmax-age\s*=\s*[1-9]\d*", cache_control):
        signals.append("freshness_lifetime_present")
        score += 1

    age = headers.get("age", "")
    if age.isdigit() and int(age) >= 0:
        signals.append("cache_age_present")
        score += 1

    for header in CACHE_STATUS_HEADERS:
        value = headers.get(header, "").lower()
        if not value:
            continue
        if any(token in value for token in ("hit", "miss", "bypass", "dynamic", "cached", "store")):
            signals.append(f"{header}_present")
            score += 1

    if headers.get("etag"):
        signals.append("etag_present")
        score += 1
    if headers.get("last-modified"):
        signals.append("last_modified_present")
        score += 1

    if varied_header and score > 0:
        varied = varied_header.lower()
        vary_tokens = _vary_tokens(headers.get("vary", ""))
        if "*" in vary_tokens:
            signals.append("vary_wildcard")
        elif varied in vary_tokens:
            signals.append(f"cache_key_includes_{varied}")
        else:
            signals.append(f"cache_key_missing_{varied}")
            score += 1

    return {"score": max(score, 0), "signals": signals}


def response_delta(
    baseline: dict[str, Any],
    variant: dict[str, Any],
    marker: str | None = None,
) -> dict[str, Any]:
    """Compare two response fingerprints and return high-signal differences."""
    signals: list[str] = []

    if baseline.get("status_code") != variant.get("status_code"):
        signals.append("status_changed")
    if baseline.get("body_hash") != variant.get("body_hash"):
        signals.append("body_hash_changed")
    if baseline.get("content_type") != variant.get("content_type"):
        signals.append("content_type_changed")
    if baseline.get("location") != variant.get("location"):
        signals.append("location_changed")
    if baseline.get("cache_control") != variant.get("cache_control") or baseline.get("vary") != variant.get("vary"):
        signals.append("cache_header_changed")

    base_len = int(baseline.get("body_len") or 0)
    variant_len = int(variant.get("body_len") or 0)
    if base_len and abs(variant_len - base_len) / max(base_len, 1) >= 0.2:
        signals.append("body_size_delta_gt_20pct")

    marker_reflected = False
    if marker:
        baseline_blob = f"{baseline.get('header_text', '')}\n{baseline.get('body_sample', '')}"
        variant_blob = f"{variant.get('header_text', '')}\n{variant.get('body_sample', '')}"
        marker_reflected = marker in variant_blob and marker not in baseline_blob
        if marker_reflected:
            signals.append("marker_reflection")

    return {
        "signals": signals,
        "marker_reflected": marker_reflected,
        "body_len_delta": variant_len - base_len,
        "status_changed": baseline.get("status_code") != variant.get("status_code"),
    }
