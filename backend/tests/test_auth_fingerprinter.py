"""
Tests for the Auth Fingerprinter and the refactored Auth Manager strategy dispatch.

Uses mock Playwright page objects to simulate different login page DOMs
without requiring a real browser.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from core.auth_fingerprinter import (
    AuthType,
    classify_login_page,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_element(
    visible=True, href=None, text="", placeholder="",
    aria_label="", name="", el_id="", autocomplete=""
):
    """Build a mock Playwright element handle."""
    el = MagicMock()
    el.is_visible = AsyncMock(return_value=visible)
    attrs = {
        "href": href,
        "placeholder": placeholder,
        "aria-label": aria_label,
        "name": name,
        "id": el_id,
        "autocomplete": autocomplete,
    }
    el.get_attribute = AsyncMock(side_effect=lambda attr: attrs.get(attr))
    el.inner_text = AsyncMock(return_value=text)
    return el


def _make_locator(elements):
    """
    Create a mock Playwright locator that wraps a list of element mocks.

    page.locator() in Playwright is *synchronous* (returns a Locator, not a coroutine),
    so we use MagicMock, not AsyncMock.
    """
    loc = MagicMock()
    loc.count = AsyncMock(return_value=len(elements))
    loc.nth = MagicMock(side_effect=lambda i: elements[i] if i < len(elements) else _make_element(visible=False))
    loc.first = elements[0] if elements else _make_element(visible=False)
    loc.inner_text = AsyncMock(return_value=elements[0].inner_text.return_value if elements else "")
    return loc


def _build_page(locator_map: dict, url: str = "https://example.com/login"):
    """
    Build a mock Playwright Page with a locator_map.

    locator_map: dict of { selector_substring: locator_mock }
    The mock routes page.locator(selector) calls based on substring matches.
    """
    page = MagicMock()
    page.url = url

    # Default empty locator
    _empty = _make_locator([])
    # Default body locator
    _body = MagicMock()
    _body.inner_text = AsyncMock(return_value="")

    def locator_side_effect(selector):
        # Check locator_map entries in order — first substring match wins
        for key, loc in locator_map.items():
            if key in selector:
                return loc
        if "body" in selector:
            return _body
        return _empty

    page.locator = MagicMock(side_effect=locator_side_effect)
    return page


# ─── AUTH_STANDARD Tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_classify_standard_form():
    """A page with both username and password fields → AUTH_STANDARD."""
    password_loc = _make_locator([_make_element(visible=True)])
    username_loc = _make_locator([_make_element(visible=True)])

    # Map: anything with "password" returns password locator,
    #       the combined username selector returns username locator,
    #       OAuth/MFA selectors return empty.
    locator_map = {
        "one-time-code": _make_locator([]),
        "a[href]": _make_locator([]),
        "a, button": _make_locator([]),
        "input[type='password']": password_loc,
        "input[type='text'], input[type='email']": username_loc,
        "label": _make_locator([]),
    }

    body = MagicMock()
    body.inner_text = AsyncMock(return_value="Welcome. Please log in.")
    locator_map["body"] = body

    page = _build_page(locator_map)
    result = await classify_login_page(page)
    assert result == AuthType.STANDARD


# ─── AUTH_OAUTH Tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_classify_oauth_by_href():
    """A page with an OAuth provider link in href → AUTH_OAUTH."""
    oauth_link = _make_element(
        visible=True,
        href="https://accounts.google.com/o/oauth2/auth?client_id=abc",
        text="Sign in with Google",
    )
    links_loc = _make_locator([oauth_link])

    locator_map = {
        "one-time-code": _make_locator([]),
        "a[href]": links_loc,
        "a, button": _make_locator([_make_element(text="Sign in with Google")]),
        "label": _make_locator([]),
    }

    body = MagicMock()
    body.inner_text = AsyncMock(return_value="")
    locator_map["body"] = body

    page = _build_page(locator_map)
    result = await classify_login_page(page)
    assert result == AuthType.OAUTH


@pytest.mark.asyncio
async def test_classify_oauth_by_button_text():
    """A page with SSO button text → AUTH_OAUTH."""
    sso_button = _make_element(visible=True, text="Continue with GitHub")

    locator_map = {
        "one-time-code": _make_locator([]),
        "a[href]": _make_locator([]),
        "a, button": _make_locator([sso_button]),
        "label": _make_locator([]),
    }

    body = MagicMock()
    body.inner_text = AsyncMock(return_value="")
    locator_map["body"] = body

    page = _build_page(locator_map)
    result = await classify_login_page(page)
    assert result == AuthType.OAUTH


# ─── AUTH_SINGLE_ID Tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_classify_single_id():
    """A page with no password field and a 'Player ID' input → AUTH_SINGLE_ID."""
    id_input = _make_element(
        visible=True,
        placeholder="Enter your Player ID",
        name="player_id",
        el_id="playerIdInput",
    )

    locator_map = {
        "one-time-code": _make_locator([]),
        "a[href]": _make_locator([]),
        "a, button": _make_locator([]),
        "input[type='password']": _make_locator([]),
        "input[type='text'], input[type='email']": _make_locator([]),
        "input[type='text'], input[type='number']": _make_locator([id_input]),
        "label": _make_locator([_make_element(text="Player ID")]),
    }

    body = MagicMock()
    body.inner_text = AsyncMock(return_value="Enter your Player ID to continue")
    locator_map["body"] = body

    page = _build_page(locator_map, url="https://game.example.com/login")
    result = await classify_login_page(page)
    assert result == AuthType.SINGLE_ID


@pytest.mark.asyncio
async def test_classify_single_id_arabic():
    """Arabic 'Player ID' keyword should also trigger AUTH_SINGLE_ID."""
    id_input = _make_element(
        visible=True,
        placeholder="معرّف اللاعب",
        name="id",
        el_id="playerId",
    )

    locator_map = {
        "one-time-code": _make_locator([]),
        "a[href]": _make_locator([]),
        "a, button": _make_locator([]),
        "input[type='password']": _make_locator([]),
        "input[type='text'], input[type='email']": _make_locator([]),
        "input[type='text'], input[type='number']": _make_locator([id_input]),
        "label": _make_locator([]),
    }

    body = MagicMock()
    body.inner_text = AsyncMock(return_value="")
    locator_map["body"] = body

    page = _build_page(locator_map, url="https://game.example.com/login")
    result = await classify_login_page(page)
    assert result == AuthType.SINGLE_ID


# ─── AUTH_MFA Tests ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_classify_mfa_by_autocomplete():
    """A page with autocomplete='one-time-code' → AUTH_MFA."""
    otp_input = _make_element(visible=True, autocomplete="one-time-code")

    locator_map = {
        "one-time-code": _make_locator([otp_input]),
    }

    body = MagicMock()
    body.inner_text = AsyncMock(return_value="")
    locator_map["body"] = body

    page = _build_page(locator_map, url="https://example.com/mfa")
    result = await classify_login_page(page)
    assert result == AuthType.MFA


@pytest.mark.asyncio
async def test_classify_mfa_by_page_text():
    """Page body containing 'verification code' → AUTH_MFA."""
    code_input = _make_element(
        visible=True, placeholder="", name="code",
    )

    locator_map = {
        "one-time-code": _make_locator([]),
        "input[type='text'], input[type='number'], input[type='tel']": _make_locator([code_input]),
    }

    body = MagicMock()
    body.inner_text = AsyncMock(
        return_value="Please enter the verification code sent to your phone."
    )
    locator_map["body"] = body

    page = _build_page(locator_map, url="https://example.com/verify")
    result = await classify_login_page(page)
    assert result == AuthType.MFA


# ─── AUTH_UNKNOWN Tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_classify_unknown_empty_page():
    """A page with no recognisable form elements → AUTH_UNKNOWN."""
    locator_map = {}

    body = MagicMock()
    body.inner_text = AsyncMock(return_value="Nothing here")
    locator_map["body"] = body

    page = _build_page(locator_map, url="https://example.com/empty")
    result = await classify_login_page(page)
    assert result == AuthType.UNKNOWN


# ─── Strategy Dispatch Tests (Auth Manager) ──────────────────────────────────

@pytest.mark.asyncio
async def test_strategy_oauth_returns_warning():
    """OAuth strategy should return a warning dict without crashing."""
    from core.auth_manager import _strategy_oauth
    page = MagicMock()
    result = await _strategy_oauth(page, {}, "https://example.com/login")
    assert "warning" in result
    assert "OAuth" in result["warning"]


@pytest.mark.asyncio
async def test_strategy_mfa_returns_warning_without_otp():
    """MFA strategy without OTP credential should return a warning."""
    from core.auth_manager import _strategy_mfa
    page = MagicMock()
    page.locator = MagicMock(return_value=_make_locator([]))
    result = await _strategy_mfa(page, {}, "https://example.com/verify")
    assert "warning" in result
    assert "MFA" in result["warning"]


@pytest.mark.asyncio
async def test_auth_type_enum_values():
    """Verify the AuthType enum has the expected string values."""
    assert AuthType.STANDARD.value == "AUTH_STANDARD"
    assert AuthType.OAUTH.value == "AUTH_OAUTH"
    assert AuthType.SINGLE_ID.value == "AUTH_SINGLE_ID"
    assert AuthType.MFA.value == "AUTH_MFA"
    assert AuthType.UNKNOWN.value == "AUTH_UNKNOWN"


@pytest.mark.asyncio
async def test_strategy_dispatch_table_complete():
    """Every AuthType should have an entry in the strategy dispatch table."""
    from core.auth_manager import _STRATEGIES
    for auth_type in AuthType:
        assert auth_type in _STRATEGIES, f"Missing strategy for {auth_type}"
