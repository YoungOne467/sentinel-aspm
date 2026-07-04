import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from core.http_client import ScannerAsyncClient
from core.auth_manager import acquire_session

@pytest.mark.asyncio
async def test_acquire_session_mock():
    """Verify playwright page execution and token/cookie extraction is correctly implemented."""
    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    mock_page = MagicMock()
    mock_page.goto = AsyncMock()
    mock_page.evaluate = AsyncMock()
    mock_page.wait_for_load_state = AsyncMock()

    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page
    mock_context.cookies.return_value = [{"name": "session_cookie", "value": "xyz123"}]

    # Mock localStorage/sessionStorage evaluate returns
    mock_page.evaluate.side_effect = [
        '{"access_token": "bearer_jwt_token_45678"}',  # localStorage
        '{}'                                            # sessionStorage
    ]

    mock_user_input = AsyncMock()
    mock_user_input.count.return_value = 1
    mock_user_input.inner_text = AsyncMock(return_value="")
    mock_user_input.get_attribute = AsyncMock(return_value="")

    mock_pass_input = AsyncMock()
    mock_pass_input.count.return_value = 1
    mock_pass_input.inner_text = AsyncMock(return_value="")
    mock_pass_input.get_attribute = AsyncMock(return_value="")

    mock_submit_btn = AsyncMock()
    mock_submit_btn.count.return_value = 1
    mock_submit_btn.inner_text = AsyncMock(return_value="")
    mock_submit_btn.get_attribute = AsyncMock(return_value="")

    def locator_mock(selector):
        if "password" in selector or "pass" in selector:
            return mock_pass_input
        elif "submit" in selector or "button" in selector:
            return mock_submit_btn
        elif "username" in selector or "user" in selector or "email" in selector or selector == "input[type='text']":
            return mock_user_input
        else:
            mock_empty = AsyncMock()
            mock_empty.count.return_value = 0
            mock_empty.inner_text = AsyncMock(return_value="")
            mock_empty.get_attribute = AsyncMock(return_value="")
            return mock_empty

    mock_page.locator.side_effect = locator_mock

    with patch("core.auth_manager.async_playwright") as mock_playwright:
        mock_p = MagicMock()
        mock_p.chromium.launch = AsyncMock(return_value=mock_browser)
        # Setup context manager double enter/exit
        mock_playwright.return_value.__aenter__.return_value = mock_p
        
        credentials = {"username": "admin", "password": "password"}
        res = await acquire_session("http://login.local", credentials)
        
        assert "headers" in res
        assert "cookies" in res
        assert res["cookies"]["session_cookie"] == "xyz123"
        assert "Authorization" in res["headers"]
        assert "bearer_jwt_token_45678" in res["headers"]["Authorization"]

@pytest.mark.asyncio
@patch("httpx.AsyncClient.request")
async def test_scanner_client_auth_injection(mock_super_request):
    """Test that auth profile tokens are injected into requests."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_super_request.return_value = mock_resp

    auth_profile = {
        "login_url": "http://login.local",
        "credentials": {"username": "admin", "password": "password"},
        "tokens": {
            "headers": {"Authorization": "Bearer initial_token"},
            "cookies": {"session_cookie": "cookie_val"}
        }
    }

    async with ScannerAsyncClient(auth_profile=auth_profile, jitter_enabled=False) as client:
        # Check constructor setup
        assert client.auth_profile == auth_profile
        
        await client.request("GET", "http://target.local/api/resource")
        
        # Verify headers were injected in the call to super().request
        called_args, called_kwargs = mock_super_request.call_args
        assert "Authorization" in called_kwargs["headers"]
        assert called_kwargs["headers"]["Authorization"] == "Bearer initial_token"
        assert client.cookies.get("session_cookie") == "cookie_val"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.request")
@patch("core.auth_manager.acquire_session")
async def test_scanner_client_auto_refresh_on_401(mock_acquire_session, mock_super_request):
    """Verify that client pauses, requests new token on 401/403, and retries request."""
    # First request: 200 OK (mark as successful endpoint)
    # Second request: 401 Unauthorized
    # Retry request: 200 OK
    resp_200 = MagicMock()
    resp_200.status_code = 200
    
    resp_401 = MagicMock()
    resp_401.status_code = 401
    
    mock_super_request.side_effect = [resp_200, resp_401, resp_200]

    # Mock session acquisition response
    mock_acquire_session.return_value = {
        "headers": {"Authorization": "Bearer refreshed_token_999"},
        "cookies": {"session_cookie": "new_cookie_val"}
    }

    auth_profile = {
        "login_url": "http://login.local",
        "credentials": {"username": "admin", "password": "password"},
        "tokens": {
            "headers": {"Authorization": "Bearer initial_token"},
            "cookies": {"session_cookie": "cookie_val"}
        }
    }

    async with ScannerAsyncClient(auth_profile=auth_profile, jitter_enabled=False) as client:
        url = "http://target.local/api/resource"
        
        # 1. Establish successful baseline
        await client.request("GET", url)
        assert url in client._successful_endpoints

        # 2. Trigger request that returns 401 and should auto-refresh
        final_resp = await client.request("GET", url)
        
        # 3. Assertions
        assert final_resp.status_code == 200
        mock_acquire_session.assert_called_once_with("http://login.local", {"username": "admin", "password": "password"})
        
        # Verify that client's auth_profile was updated
        assert client.auth_profile["tokens"]["headers"]["Authorization"] == "Bearer refreshed_token_999"
        assert client.cookies.get("session_cookie") == "new_cookie_val"
