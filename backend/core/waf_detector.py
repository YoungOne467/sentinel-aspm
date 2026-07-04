"""
WAF fingerprinting and scanner adaptation hints.
"""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx

NOISY_PARAMETER = ("id", "<script>alert(1)</script>")

WAF_ADAPTATION = {
    "cloudflare": {"concurrency_limit": 3, "jitter_range": [1.0, 3.0], "payload_encoding": "standard"},
    "aws_waf": {"concurrency_limit": 2, "jitter_range": [1.2, 2.8], "payload_encoding": "double_url"},
    "akamai": {"concurrency_limit": 2, "jitter_range": [1.5, 3.5], "payload_encoding": "standard"},
    "imperva": {"concurrency_limit": 2, "jitter_range": [1.5, 4.0], "payload_encoding": "unicode"},
    "generic": {"concurrency_limit": 4, "jitter_range": [0.8, 2.5], "payload_encoding": "standard"},
}

_WAF_PROFILE_CACHE: dict[str, dict[str, Any]] = {}


async def detect_waf(url: str) -> dict[str, Any]:
    """
    Fingerprint a target by comparing a benign request with a noisy blocked-input probe.
    """
    benign_url = strip_query(url)
    noisy_url = build_noisy_probe_url(url)
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
        benign = await client.get(benign_url, headers={"User-Agent": "SENTINEL-WAF-Fingerprint"})
        noisy = await client.get(noisy_url, headers={"User-Agent": "SENTINEL-WAF-Fingerprint"})

    result = fingerprint_waf(benign, noisy)
    result.update(
        {
            "url": url,
            "benign_url": benign_url,
            "probe_url": noisy_url,
            "benign_status": benign.status_code,
            "block_status": noisy.status_code,
        }
    )
    if result["detected"]:
        cache_waf_profile(url, result)
    return result


def fingerprint_waf(benign_response: Any, noisy_response: Any) -> dict[str, Any]:
    headers = response_headers_text(benign_response) + "\n" + response_headers_text(noisy_response)
    body = f"{getattr(benign_response, 'text', '')}\n{getattr(noisy_response, 'text', '')}".lower()
    status_code = getattr(noisy_response, "status_code", None)

    candidates = {
        "cloudflare": score_signatures(
            headers,
            body,
            ("server: cloudflare", "cf-ray", "cf-cache-status"),
            ("cloudflare", "attention required"),
        ),
        "aws_waf": score_signatures(
            headers,
            body,
            ("x-amz-cf-id", "x-amzn-requestid", "x-amzn-waf-action"),
            ("aws waf", "request blocked"),
        ),
        "akamai": score_signatures(
            headers,
            body,
            ("akamai", "server: akamaighost"),
            ("access denied", "reference #"),
        ),
        "imperva": score_signatures(
            headers,
            body,
            ("x-iinfo", "incap_ses", "visid_incap"),
            ("imperva", "incapsula", "request unsuccessful"),
        ),
    }
    provider, score = max(candidates.items(), key=lambda item: item[1])
    blocked = status_code in {403, 406, 429}
    detected = score > 0 or blocked
    if score == 0 and blocked:
        provider = "generic"

    confidence = min(1.0, (score * 0.25) + (0.25 if blocked else 0.0))
    indicators = build_indicators(provider, headers, body, blocked)
    return {
        "detected": detected,
        "provider": provider if detected else "none",
        "confidence": confidence if detected else 0.0,
        "block_status": status_code,
        "indicators": indicators,
        "adaptation": WAF_ADAPTATION.get(provider, WAF_ADAPTATION["generic"]) if detected else {},
    }


def score_signatures(headers: str, body: str, header_needles: tuple[str, ...], body_needles: tuple[str, ...]) -> int:
    lowered_headers = headers.lower()
    return sum(1 for needle in header_needles if needle in lowered_headers) + sum(
        1 for needle in body_needles if needle in body
    )


def build_indicators(provider: str, headers: str, body: str, blocked: bool) -> list[str]:
    indicators: list[str] = []
    lowered_headers = headers.lower()
    if blocked:
        indicators.append("blocking_status")
    for marker in ("cf-ray", "x-amz-cf-id", "x-amzn-waf-action", "akamaighost", "x-iinfo"):
        if marker in lowered_headers:
            indicators.append(marker)
    if provider in body:
        indicators.append(f"{provider}_block_page")
    return indicators


def response_headers_text(response: Any) -> str:
    headers = getattr(response, "headers", {}) or {}
    return "\n".join(f"{name}: {value}" for name, value in dict(headers).items())


def strip_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", parts.fragment))


def build_noisy_probe_url(url: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append(NOISY_PARAMETER)
    encoded_query = urlencode(query)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", encoded_query, parts.fragment))


def cache_waf_profile(url: str, profile: dict[str, Any]) -> None:
    _WAF_PROFILE_CACHE[cache_key(url)] = dict(profile)


def get_cached_waf_profile(url: str) -> dict[str, Any] | None:
    return _WAF_PROFILE_CACHE.get(cache_key(url))


def clear_waf_profile_cache() -> None:
    _WAF_PROFILE_CACHE.clear()


def cache_key(url: str) -> str:
    parts = urlsplit(url if "://" in url else f"https://{url}")
    return parts.netloc.lower() or parts.path.lower()


def adapt_url_for_waf(url: str, profile: dict[str, Any] | None) -> str:
    if not profile or not profile.get("detected"):
        return url
    encoding = (profile.get("adaptation") or {}).get("payload_encoding")
    if encoding == "double_url":
        return encode_query_values(url, passes=2)
    if encoding == "unicode":
        return unicode_escape_query_values(url)
    return url


def encode_query_values(url: str, *, passes: int) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return url
    encoded_pairs = []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        encoded_value = value
        for _ in range(passes):
            encoded_value = quote(encoded_value, safe="")
        encoded_pairs.append((name, encoded_value))
    query = "&".join(f"{quote(name, safe='')}={value}" for name, value in encoded_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def unicode_escape_query_values(url: str) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return url
    encoded_pairs = []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        escaped = "".join(f"%u{ord(char):04x}" if char in "<>\"'" else quote(char, safe="") for char in value)
        encoded_pairs.append((name, escaped))
    query = "&".join(f"{quote(name, safe='')}={value}" for name, value in encoded_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def profile_cache_digest() -> str:
    return hashlib.sha256(repr(sorted(_WAF_PROFILE_CACHE.items())).encode("utf-8")).hexdigest()
