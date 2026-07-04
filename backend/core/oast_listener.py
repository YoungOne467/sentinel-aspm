"""
Out-of-Band Application Security Testing (OAST) Listener.

This module runs a lightweight async HTTP server on a separate port.
When the active scanner injects payloads containing URLs that point to this
listener, any callback received from the target server proves the existence
of a blind vulnerability (SSRF, Blind XXE, RCE, Log4Shell, etc.)
with zero false-positive risk.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from aiohttp import web

logger = logging.getLogger(__name__)

# Global registry of received interactions
_interactions: list[dict] = []
_runner: web.AppRunner | None = None

OAST_PORT = 8081
PUBLIC_OAST_DOMAIN = "oob.invalid"
_oast_settings_cache: dict[str, Any] | None = None
_fallback_warning_emitted = False


def get_oast_settings_path() -> Path:
    configured = os.getenv("SENTINEL_OAST_SETTINGS_PATH", "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[2] / "scratch" / "oast_settings.json"


def reload_oast_settings() -> dict[str, Any]:
    """Reload OAST settings from file/environment and return the sanitized view."""
    global _oast_settings_cache, _fallback_warning_emitted
    _oast_settings_cache = None
    _fallback_warning_emitted = False
    return get_oast_settings()


def get_oast_settings(*, include_token: bool = False) -> dict[str, Any]:
    """Return active OAST configuration, preferring dynamic settings over environment defaults."""
    global _oast_settings_cache
    if _oast_settings_cache is None:
        _oast_settings_cache = load_oast_settings()
    return sanitize_oast_settings(_oast_settings_cache, include_token=include_token)


def update_oast_settings(domain: str, token: str | None = None, provider: str | None = None) -> dict[str, Any]:
    """Persist and activate a private OAST configuration."""
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        raise ValueError("OAST domain is required")
    settings = build_settings(
        domain=clean_domain,
        token=(token or "").strip(),
        provider=(provider or "private-interactsh").strip() or "private-interactsh",
        private=True,
        source="settings_file",
    )
    path = get_oast_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    global _oast_settings_cache
    _oast_settings_cache = settings
    return sanitize_oast_settings(settings)


def load_oast_settings() -> dict[str, Any]:
    file_settings = load_oast_settings_file()
    if file_settings:
        return build_settings(
            domain=normalize_domain(file_settings.get("domain")),
            token=str(file_settings.get("token") or ""),
            provider=str(file_settings.get("provider") or "private-interactsh"),
            private=bool(file_settings.get("private", True)),
            source="settings_file",
            poll_url=file_settings.get("poll_url"),
            register_url=file_settings.get("register_url"),
        )

    private_domain = normalize_domain(os.getenv("PRIVATE_OAST_DOMAIN"))
    if private_domain:
        return build_settings(
            domain=private_domain,
            token=os.getenv("PRIVATE_OAST_TOKEN", ""),
            provider=os.getenv("PRIVATE_OAST_PROVIDER", "private-interactsh"),
            private=True,
            source="environment",
            poll_url=os.getenv("PRIVATE_OAST_POLL_URL"),
            register_url=os.getenv("PRIVATE_OAST_REGISTER_URL"),
        )

    public_domain = normalize_domain(os.getenv("OOB_BASE_DOMAIN")) or PUBLIC_OAST_DOMAIN
    warn_public_fallback()
    return build_settings(
        domain=public_domain,
        token=os.getenv("OOB_POLL_TOKEN") or os.getenv("INTERACTSH_TOKEN") or "",
        provider=os.getenv("OOB_PROVIDER", "interactsh-public"),
        private=False,
        source="public_fallback",
        poll_url=os.getenv("OOB_POLL_URL"),
        register_url=os.getenv("OOB_REGISTER_URL"),
    )


def load_oast_settings_file() -> dict[str, Any] | None:
    path = get_oast_settings_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not load OAST settings file %s: %s", path, exc)
        return None


def build_settings(
    *,
    domain: str,
    token: str = "",
    provider: str,
    private: bool,
    source: str,
    poll_url: str | None = None,
    register_url: str | None = None,
) -> dict[str, Any]:
    clean_domain = normalize_domain(domain) or PUBLIC_OAST_DOMAIN
    return {
        "domain": clean_domain,
        "token": token or "",
        "provider": provider,
        "private": private,
        "source": source,
        "poll_url": (poll_url or f"https://{clean_domain}/poll").strip(),
        "register_url": (register_url or f"https://{clean_domain}/register").strip(),
    }


def sanitize_oast_settings(settings: dict[str, Any], *, include_token: bool = False) -> dict[str, Any]:
    sanitized = dict(settings)
    token = str(sanitized.get("token") or "")
    sanitized["token_configured"] = bool(token)
    if not include_token:
        sanitized.pop("token", None)
    return sanitized


def normalize_domain(value: Any) -> str:
    domain = str(value or "").strip()
    domain = domain.removeprefix("https://").removeprefix("http://").strip("/")
    return domain.lower()


def warn_public_fallback() -> None:
    global _fallback_warning_emitted
    if _fallback_warning_emitted:
        return
    logger.warning(
        "PRIVATE_OAST_DOMAIN is not configured; falling back to public OAST settings. "
        "Target callback metadata may leave this environment."
    )
    _fallback_warning_emitted = True


def get_interactions() -> list[dict]:
    """Return a copy of all recorded OAST interactions."""
    return list(_interactions)


def clear_interactions() -> None:
    """Clear all recorded OAST interactions."""
    _interactions.clear()


def has_interaction_for(token: str) -> bool:
    """Check whether a specific token was seen in any OAST callback."""
    return any(token in str(i) for i in _interactions)


# ── HTTP Handler ──────────────────────────────────────────────────────────

async def _handle_oast_callback(request: web.Request) -> web.Response:
    """
    Catch-all handler. Anything that hits this server is an OAST interaction.
    """
    body = ""
    try:
        body = await request.text()
    except Exception:
        pass

    interaction = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": str(request.path),
        "query": str(request.query_string),
        "headers": dict(request.headers),
        "body": body[:2048],  # cap body to avoid memory issues
        "remote_ip": request.remote,
    }
    _interactions.append(interaction)
    logger.warning(f"OAST INTERACTION RECEIVED from {request.remote}: "
                   f"{request.method} {request.path}")
    return web.Response(text="ok")


# ── Lifecycle ─────────────────────────────────────────────────────────────

async def start_oast_listener() -> None:
    """Start the OAST HTTP listener on OAST_PORT."""
    global _runner
    app = web.Application()
    # Catch every possible path
    app.router.add_route("*", "/{path_info:.*}", _handle_oast_callback)

    _runner = web.AppRunner(app)
    await _runner.setup()
    site = web.TCPSite(_runner, "0.0.0.0", OAST_PORT)
    await site.start()
    logger.info("OAST Listener started on port %s", OAST_PORT)


async def stop_oast_listener() -> None:
    """Gracefully shut down the OAST listener."""
    global _runner
    if _runner:
        await _runner.cleanup()
        _runner = None
        logger.info("OAST Listener stopped.")
