"""Per-scan request context.

Scanner modules use httpx directly, so this module provides a scoped way for
the FastAPI entrypoint to attach optional authenticated headers to all requests
created during a scan task.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import re
from typing import Iterator


_SCAN_HEADERS: ContextVar[dict[str, str]] = ContextVar("aspm_scan_headers", default={})
_SCAN_INTENSITY: ContextVar[str] = ContextVar("aspm_scan_intensity", default="normal")
_SCAN_SCOPE: ContextVar[str | None] = ContextVar("aspm_scan_scope", default=None)

HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
DISALLOWED_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def sanitize_scan_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Return request headers safe to apply to scanner traffic."""
    sanitized: dict[str, str] = {}
    for raw_name, raw_value in (headers or {}).items():
        name = str(raw_name).strip()
        if not name or not HEADER_NAME_RE.fullmatch(name):
            continue
        if name.lower() in DISALLOWED_HEADERS:
            continue
        value = str(raw_value).replace("\r", "").replace("\n", "").strip()
        if value:
            sanitized[name] = value
    return sanitized


def get_scan_context_headers() -> dict[str, str]:
    return dict(_SCAN_HEADERS.get() or {})


def get_scan_intensity() -> str:
    return _SCAN_INTENSITY.get()


def get_scan_scope() -> str | None:
    return _SCAN_SCOPE.get()


@contextmanager
def scan_header_context(headers: dict[str, str] | None) -> Iterator[None]:
    token = _SCAN_HEADERS.set(sanitize_scan_headers(headers))
    try:
        yield
    finally:
        _SCAN_HEADERS.reset(token)


@contextmanager
def scan_intensity_context(intensity: str) -> Iterator[None]:
    token = _SCAN_INTENSITY.set(intensity or "normal")
    try:
        yield
    finally:
        _SCAN_INTENSITY.reset(token)


@contextmanager
def scan_scope_context(scope_url: str | None) -> Iterator[None]:
    token = _SCAN_SCOPE.set(scope_url)
    try:
        yield
    finally:
        _SCAN_SCOPE.reset(token)

