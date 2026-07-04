"""
Auth Manager — adaptive session acquisition engine.

Uses the Auth Fingerprinter to classify the login page DOM before acting,
then dispatches to the correct strategy:

    AUTH_STANDARD  → username + password injection
    AUTH_SINGLE_ID → single credential field injection (Player ID, etc.)
    AUTH_OAUTH     → log warning, pause auth queue (manual intervention)
    AUTH_MFA       → log warning, attempt to wait for user-supplied OTP
    AUTH_UNKNOWN   → fall back to standard with best-effort selectors
"""

from __future__ import annotations

import json
import logging
import asyncio
from typing import TYPE_CHECKING, Dict, Any, Optional

from playwright.async_api import async_playwright

if TYPE_CHECKING:
    from playwright.async_api import Page, BrowserContext

from core.auth_fingerprinter import classify_login_page, AuthType

logger = logging.getLogger(__name__)


# ─── Selector Banks ───────────────────────────────────────────────────────────

USER_SELECTORS = [
    "input[type='text']", "input[name='username']", "input[name='user']",
    "input[type='email']", "input[name='email']", "input[id='username']",
    "input[placeholder*='username' i]", "input[placeholder*='email' i]",
    "input[placeholder*='login' i]",
]

PASS_SELECTORS = [
    "input[type='password']", "input[name='password']", "input[id='password']",
    "input[placeholder*='password' i]", "input[placeholder*='pass' i]",
]

SUBMIT_SELECTORS = [
    "button[type='submit']", "input[type='submit']", "button",
    "input[value*='login' i]", "input[value*='sign' i]",
    "button:has-text('login' i)", "button:has-text('sign' i)",
    "button:has-text('submit' i)", "button:has-text('continue' i)",
    "button:has-text('next' i)",
]

SINGLE_ID_SELECTORS = [
    "input[type='text']", "input[type='number']", "input[type='tel']",
    "input:not([type])",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def get_target_id_by_url(url: str) -> Optional[str]:
    """Resolve the SENTINEL target ID for a given URL."""
    from urllib.parse import urlsplit
    from sqlalchemy import select
    from core.database import AsyncSessionLocal
    from core.models import Target
    try:
        parsed = urlsplit(url)
        host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split(":")[0]
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Target.id).where(Target.host == host))
            target_id = result.scalars().first()
            if not target_id:
                # Fallback: get first target
                result = await session.execute(select(Target.id))
                target_id = result.scalars().first()
            return target_id
    except Exception as e:
        logger.error("Error resolving target_id for url %s: %s", url, e)
    return None


async def _find_first_visible(page: Page, selectors: list[str]):
    """Return the first visible Playwright locator matching any selector."""
    for sel in selectors:
        try:
            locator = page.locator(sel)
            if await locator.count() > 0:
                first = locator.first
                if await first.is_visible():
                    return first
        except Exception:
            continue
    return None


async def _click_submit(page: Page, fallback_field=None):
    """Locate and click the submit button, falling back to Enter key."""
    submit_el = await _find_first_visible(page, SUBMIT_SELECTORS)

    if submit_el:
        try:
            await asyncio.gather(
                page.wait_for_load_state("networkidle", timeout=10000),
                submit_el.click(),
            )
            return
        except Exception:
            pass

    # Fallback: press Enter on the provided field (or body)
    target = fallback_field or page.locator("body")
    await asyncio.gather(
        page.wait_for_load_state("networkidle", timeout=10000),
        target.press("Enter"),
    )


async def _extract_session_artifacts(page: Page, context: BrowserContext) -> Dict[str, Any]:
    """Extract cookies, storage tokens, and Authorization headers after login."""
    cookies = await context.cookies()
    cookies_dict = {c["name"]: c["value"] for c in cookies}

    local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
    session_storage = await page.evaluate("() => JSON.stringify(sessionStorage)")

    local_storage_dict = {}
    session_storage_dict = {}
    if local_storage:
        try:
            local_storage_dict = json.loads(local_storage)
        except Exception:
            pass
    if session_storage:
        try:
            session_storage_dict = json.loads(session_storage)
        except Exception:
            pass

    auth_headers: Dict[str, str] = {}
    all_storage = {**local_storage_dict, **session_storage_dict}

    for key, val in all_storage.items():
        if not isinstance(val, str):
            continue
        key_lower = key.lower()
        if any(tok in key_lower for tok in ("token", "jwt", "auth", "access", "session")):
            val_strip = val.strip()
            if len(val_strip) > 20:
                if val_strip.startswith("Bearer "):
                    auth_headers["Authorization"] = val_strip
                else:
                    if not val_strip.startswith(("{", "[")):
                        auth_headers["Authorization"] = f"Bearer {val_strip}"
                logger.info("Extracted authorization header from storage key: %s", key)
                break

    logger.info(
        "Session artifacts extracted. Cookies: %d, Headers: %d",
        len(cookies_dict), len(auth_headers),
    )
    return {"headers": auth_headers, "cookies": cookies_dict}


async def _attach_websocket_monitor(page: Page, login_url: str):
    """Hook the WebSocket analyzer to capture post-login socket telemetry."""
    try:
        from core.websocket_analyzer import monitor_websockets
        target_id = await get_target_id_by_url(login_url)
        if target_id:
            monitor_websockets(page, target_id)
            await asyncio.sleep(5.0)
    except Exception as ws_err:
        logger.debug("Failed to initialize WebSocket analyzer: %s", ws_err)


# ─── Strategy Implementations ────────────────────────────────────────────────

async def _strategy_standard(page: Page, credentials: dict, login_url: str) -> Dict[str, Any]:
    """Standard username + password form injection."""
    user_el = await _find_first_visible(page, USER_SELECTORS)
    pass_el = await _find_first_visible(page, PASS_SELECTORS)

    if not user_el or not pass_el:
        raise ValueError(
            "AUTH_STANDARD detected but could not locate username and password inputs."
        )

    await user_el.fill(credentials.get("username", ""))
    await pass_el.fill(credentials.get("password", ""))
    await _click_submit(page, fallback_field=pass_el)

    return {}  # signals success; artifacts extracted by caller


async def _strategy_single_id(page: Page, credentials: dict, login_url: str) -> Dict[str, Any]:
    """Single-input ID injection (Player ID, Account ID, etc.)."""
    logger.info("AUTH_SINGLE_ID strategy: injecting single credential field.")

    # Find the solitary visible text input
    id_el = None
    for sel in SINGLE_ID_SELECTORS:
        try:
            locator = page.locator(sel)
            count = await locator.count()
            for i in range(count):
                el = locator.nth(i)
                if await el.is_visible():
                    id_el = el
                    break
            if id_el:
                break
        except Exception:
            continue

    if not id_el:
        raise ValueError(
            "AUTH_SINGLE_ID detected but could not locate the ID input field."
        )

    # Use the 'username' credential key, or a dedicated 'player_id' / 'account_id' key
    credential_value = (
        credentials.get("player_id")
        or credentials.get("account_id")
        or credentials.get("user_id")
        or credentials.get("code")
        or credentials.get("username", "")
    )

    await id_el.fill(credential_value)
    await _click_submit(page, fallback_field=id_el)

    return {}


async def _strategy_oauth(page: Page, credentials: dict, login_url: str) -> Dict[str, Any]:
    """OAuth / SSO — cannot be fully automated safely."""
    logger.warning(
        "OAuth login detected at %s. Manual intervention required. "
        "Fully automating third-party OAuth flows violates most provider ToS "
        "and may require complex 2FA bypassing.",
        login_url,
    )
    return {"warning": "OAuth login detected. Manual intervention required."}


async def _strategy_mfa(page: Page, credentials: dict, login_url: str) -> Dict[str, Any]:
    """MFA step — log and attempt standard flow first, then warn about OTP."""
    logger.warning(
        "MFA / 2FA step detected at %s. The scan may require a pre-filled OTP "
        "or authenticator token in credentials['otp'].",
        login_url,
    )
    # If OTP is provided, try injecting it
    otp_value = credentials.get("otp") or credentials.get("totp") or credentials.get("code")
    if otp_value:
        otp_el = await _find_first_visible(page, [
            "input[autocomplete='one-time-code']",
            "input[type='text']",
            "input[type='number']",
            "input[type='tel']",
        ])
        if otp_el:
            await otp_el.fill(str(otp_value))
            await _click_submit(page, fallback_field=otp_el)
            return {}

    return {"warning": "MFA detected. Provide 'otp' in credentials for automated injection."}


# Strategy dispatch table
_STRATEGIES = {
    AuthType.STANDARD: _strategy_standard,
    AuthType.SINGLE_ID: _strategy_single_id,
    AuthType.OAUTH: _strategy_oauth,
    AuthType.MFA: _strategy_mfa,
    AuthType.UNKNOWN: _strategy_standard,  # best-effort fallback
}


# ─── Public API ────────────────────────────────────────────────────────────────

async def acquire_session(login_url: str, credentials: dict) -> dict:
    """
    Launches a headless browser, fingerprints the login page, dispatches to
    the appropriate auth strategy, and extracts session artifacts.
    """
    logger.info("Acquiring authentication session for target login URL: %s", login_url)

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
        except Exception as e:
            logger.error(
                "Playwright launch failed: %s. Verify browsers are installed "
                "via 'playwright install'.", e,
            )
            raise

        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        try:
            # 1. Navigate to login page
            await page.goto(login_url, wait_until="networkidle", timeout=30000)

            # 2. Fingerprint the login page
            auth_type = await classify_login_page(page)
            logger.info(
                "Login page classified as %s for %s",
                auth_type.value, login_url,
            )

            # 3. Dispatch to the correct strategy
            strategy_fn = _STRATEGIES.get(auth_type, _strategy_standard)
            strategy_result = await strategy_fn(page, credentials, login_url)

            # If the strategy returned a warning (OAuth, MFA without OTP),
            # return it early without attempting artifact extraction.
            if strategy_result.get("warning"):
                return {
                    "auth_type": auth_type.value,
                    "headers": {},
                    "cookies": {},
                    **strategy_result,
                }

            # 4. Attach WebSocket monitor post-login
            await _attach_websocket_monitor(page, login_url)

            # 5. Extract session artifacts
            artifacts = await _extract_session_artifacts(page, context)
            artifacts["auth_type"] = auth_type.value

            logger.info(
                "Session acquired successfully via %s. Cookies: %d, Headers: %d",
                auth_type.value,
                len(artifacts.get("cookies", {})),
                len(artifacts.get("headers", {})),
            )
            return artifacts

        finally:
            await browser.close()
