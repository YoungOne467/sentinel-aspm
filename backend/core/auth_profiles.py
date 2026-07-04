"""Authentication profile handling for multi-persona scans."""

from __future__ import annotations

from contextlib import contextmanager
import re
from typing import Any, Iterator

from core.request_context import sanitize_scan_headers, scan_header_context


PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")


def _profile_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    if "headers" in value and isinstance(value.get("headers"), dict):
        headers = sanitize_scan_headers(value.get("headers"))
        cookie = value.get("cookie") or value.get("cookies")
        if cookie and "Cookie" not in headers:
            headers["Cookie"] = str(cookie).replace("\r", "").replace("\n", "").strip()
        return sanitize_scan_headers(headers)
    return sanitize_scan_headers(value)


def sanitize_auth_profiles(
    profiles: dict[str, Any] | None,
    *,
    legacy_headers: dict[str, str] | None = None,
) -> dict[str, dict[str, str]]:
    """Normalize named auth profiles, always including anonymous."""
    normalized: dict[str, dict[str, str]] = {"anonymous": {}}
    for raw_name, raw_value in (profiles or {}).items():
        name = str(raw_name).strip()
        if not name or not PROFILE_NAME_RE.fullmatch(name):
            continue
        headers = _profile_headers(raw_value)
        if headers or name == "anonymous":
            normalized[name] = headers

    if legacy_headers and "primary" not in normalized:
        headers = sanitize_scan_headers(legacy_headers)
        if headers:
            normalized["primary"] = headers

    return normalized


def get_auth_profile_headers(profiles: dict[str, dict[str, str]] | None, name: str | None) -> dict[str, str]:
    if not profiles:
        return {}
    return dict(profiles.get(name or "anonymous") or {})


@contextmanager
def auth_profile_context(profiles: dict[str, dict[str, str]] | None, name: str | None) -> Iterator[None]:
    with scan_header_context(get_auth_profile_headers(profiles, name)):
        yield
