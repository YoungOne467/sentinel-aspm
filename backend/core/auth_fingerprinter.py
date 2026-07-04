"""
Auth Fingerprinter — DOM heuristic classifier for login page strategy.

Analyses an active Playwright page context and returns a classification
that tells the auth engine *how* to proceed:

    AUTH_STANDARD   — username + password form (most common)
    AUTH_OAUTH      — third-party OAuth / SSO provider buttons detected
    AUTH_SINGLE_ID  — solitary text input (Player ID, Account ID, etc.)
    AUTH_MFA        — multi-factor auth step (OTP / TOTP field detected)
    AUTH_UNKNOWN    — no recognisable pattern found
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)


# ─── Classification Enum ──────────────────────────────────────────────────────

class AuthType(str, Enum):
    STANDARD = "AUTH_STANDARD"
    OAUTH = "AUTH_OAUTH"
    SINGLE_ID = "AUTH_SINGLE_ID"
    MFA = "AUTH_MFA"
    UNKNOWN = "AUTH_UNKNOWN"


# ─── OAuth Provider Signatures ────────────────────────────────────────────────
# Partial URL fragments that indicate third-party OAuth/SSO flows.

OAUTH_HREF_SIGNATURES: List[str] = [
    "accounts.google.com",
    "github.com/login/oauth",
    "facebook.com/dialog",
    "facebook.com/v",                   # Graph API OAuth
    "login.microsoftonline.com",
    "appleid.apple.com/auth",
    "api.twitter.com/oauth",
    "x.com/i/oauth",
    "discord.com/api/oauth",
    "discord.com/oauth",
    "login.yahoo.com",
    "slack.com/oauth",
    "gitlab.com/oauth",
    "bitbucket.org/site/oauth",
    "auth0.com",
    "okta.com",
    "onelogin.com",
    "keycloak",
    "cognito",
    "sso.",                             # generic SSO subdomain
]

# Button / link text hints for SSO (case-insensitive substring match).
OAUTH_TEXT_SIGNATURES: List[str] = [
    "sign in with google",
    "sign in with github",
    "sign in with facebook",
    "sign in with microsoft",
    "sign in with apple",
    "login with google",
    "login with github",
    "login with facebook",
    "login with microsoft",
    "login with apple",
    "continue with google",
    "continue with github",
    "continue with facebook",
    "continue with microsoft",
    "continue with apple",
    "sign in with sso",
    "login with sso",
    "single sign-on",
    "enterprise login",
    "saml",
]

# ─── Single-ID Keywords ──────────────────────────────────────────────────────
# Placeholder / label text that suggests a non-password, single-identifier flow.

SINGLE_ID_KEYWORDS: List[str] = [
    "player id",
    "account id",
    "user id",
    "member id",
    "game id",
    "code",
    "access code",
    "invitation code",
    "invite code",
    "pin",
    # Localised variants
    "معرّف اللاعب",       # Arabic — "Player ID"
    "معرف اللاعب",
    "アカウントID",         # Japanese
    "플레이어 ID",          # Korean
    "ID игрока",           # Russian
    "ID du joueur",        # French
    "Spieler-ID",          # German
    "ID del jugador",      # Spanish
]

# ─── MFA Keywords ─────────────────────────────────────────────────────────────

MFA_KEYWORDS: List[str] = [
    "one-time",
    "otp",
    "totp",
    "verification code",
    "authenticator",
    "two-factor",
    "2fa",
    "mfa",
    "6-digit",
    "security code",
]


# ─── Public API ────────────────────────────────────────────────────────────────

async def classify_login_page(page: Page) -> AuthType:
    """
    Inspect the currently loaded page and return the most likely auth flow type.

    Priority order (first match wins):
        1. MFA — if we detect an OTP / 2FA input
        2. OAuth — if SSO provider links or buttons are present
        3. Standard — password + username/email fields
        4. Single-ID — solitary text input with ID-like keywords
        5. Unknown — fallback
    """
    try:
        classification = await _classify(page)
        logger.info("Auth fingerprint result: %s for %s", classification.value, page.url)
        return classification
    except Exception as exc:
        logger.error("Auth fingerprinting failed: %s", exc)
        return AuthType.UNKNOWN


async def _classify(page: Page) -> AuthType:
    """Internal classification logic, separated for clean error boundaries."""

    # ── 1. MFA Detection ──────────────────────────────────────────────────
    if await _detect_mfa(page):
        return AuthType.MFA

    # ── 2. OAuth / SSO Detection ──────────────────────────────────────────
    if await _detect_oauth(page):
        return AuthType.OAUTH

    # ── 3. Standard Form Detection ────────────────────────────────────────
    has_password = await _has_visible_element(page, "input[type='password']")
    has_username = await _has_visible_element(
        page,
        "input[type='text'], input[type='email'], "
        "input[name='username'], input[name='user'], "
        "input[name='email'], input[id='username'], "
        "input[id='email']",
    )
    if has_password and has_username:
        return AuthType.STANDARD

    # ── 4. Single-ID Detection ────────────────────────────────────────────
    if await _detect_single_id(page):
        return AuthType.SINGLE_ID

    # If there's a password field but we couldn't find a username,
    # still treat as standard (some forms rely on autocomplete or JS).
    if has_password:
        return AuthType.STANDARD

    return AuthType.UNKNOWN


# ─── Heuristic Helpers ─────────────────────────────────────────────────────────

async def _has_visible_element(page: Page, selector: str) -> bool:
    """Return True if at least one *visible* element matches ``selector``."""
    try:
        locator = page.locator(selector)
        count = await locator.count()
        for i in range(count):
            if await locator.nth(i).is_visible():
                return True
    except Exception:
        pass
    return False


async def _detect_oauth(page: Page) -> bool:
    """Scan links and buttons for OAuth provider URL fragments or text hints."""
    try:
        # Check all <a> href attributes
        links = page.locator("a[href]")
        link_count = await links.count()
        for i in range(min(link_count, 50)):  # cap to avoid huge DOMs
            href = await links.nth(i).get_attribute("href") or ""
            href_lower = href.lower()
            for sig in OAUTH_HREF_SIGNATURES:
                if sig in href_lower:
                    logger.debug("OAuth signature matched in href: %s", sig)
                    return True

        # Check button / link *text* for SSO keywords
        clickables = page.locator("a, button")
        clickable_count = await clickables.count()
        for i in range(min(clickable_count, 50)):
            text = (await clickables.nth(i).inner_text() or "").lower().strip()
            for sig in OAUTH_TEXT_SIGNATURES:
                if sig in text:
                    logger.debug("OAuth text signature matched: '%s'", sig)
                    return True
    except Exception as exc:
        logger.debug("OAuth detection error: %s", exc)

    return False


async def _detect_single_id(page: Page) -> bool:
    """
    Detect a single text/number input with ID-like keywords and no password
    field on the page.
    """
    try:
        has_password = await _has_visible_element(page, "input[type='password']")
        if has_password:
            return False

        # Gather all visible text-like inputs
        text_inputs = page.locator(
            "input[type='text'], input[type='number'], input[type='tel'], "
            "input:not([type])"
        )
        visible_count = 0
        matched_keyword = False

        count = await text_inputs.count()
        for i in range(count):
            el = text_inputs.nth(i)
            if not await el.is_visible():
                continue
            visible_count += 1

            # Check placeholder and aria-label for ID keywords
            placeholder = (await el.get_attribute("placeholder") or "").lower()
            aria_label = (await el.get_attribute("aria-label") or "").lower()
            name_attr = (await el.get_attribute("name") or "").lower()
            id_attr = (await el.get_attribute("id") or "").lower()

            combined = f"{placeholder} {aria_label} {name_attr} {id_attr}"
            for kw in SINGLE_ID_KEYWORDS:
                if kw.lower() in combined:
                    matched_keyword = True
                    break

        # Also scan nearby labels
        if not matched_keyword:
            labels = page.locator("label")
            label_count = await labels.count()
            for i in range(min(label_count, 20)):
                text = (await labels.nth(i).inner_text() or "").lower()
                for kw in SINGLE_ID_KEYWORDS:
                    if kw.lower() in text:
                        matched_keyword = True
                        break
                if matched_keyword:
                    break

        # Single visible text input + keyword match → Single ID flow
        if visible_count >= 1 and visible_count <= 2 and matched_keyword:
            return True
    except Exception as exc:
        logger.debug("Single-ID detection error: %s", exc)

    return False


async def _detect_mfa(page: Page) -> bool:
    """
    Detect MFA / OTP input fields — typically a single short input asking
    for a verification code or 6-digit PIN.
    """
    try:
        # Check for OTP-specific input attributes
        otp_inputs = page.locator("input[autocomplete='one-time-code']")
        if await otp_inputs.count() > 0:
            return True

        # Scan all text-like inputs for MFA keywords
        text_inputs = page.locator(
            "input[type='text'], input[type='number'], input[type='tel'], "
            "input:not([type])"
        )
        count = await text_inputs.count()
        for i in range(count):
            el = text_inputs.nth(i)
            if not await el.is_visible():
                continue
            placeholder = (await el.get_attribute("placeholder") or "").lower()
            aria_label = (await el.get_attribute("aria-label") or "").lower()
            name_attr = (await el.get_attribute("name") or "").lower()
            combined = f"{placeholder} {aria_label} {name_attr}"
            for kw in MFA_KEYWORDS:
                if kw in combined:
                    return True

        # Scan page text for MFA prompts
        body_text = await page.locator("body").inner_text()
        body_lower = (body_text or "")[:3000].lower()
        mfa_phrases = [
            "enter the code",
            "verification code",
            "authenticator app",
            "two-factor",
            "2-step verification",
            "enter otp",
            "one-time password",
        ]
        for phrase in mfa_phrases:
            if phrase in body_lower:
                return True
    except Exception as exc:
        logger.debug("MFA detection error: %s", exc)

    return False
