import pytest
import sys
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

# This test file mocks whatever is necessary to import get_oast_settings_service
mock_db = MagicMock()
mock_db.AsyncSessionLocal = MagicMock()
mock_db.batch_writer = MagicMock()
mock_db.Base = MagicMock()
mock_db.get_db = MagicMock()
mock_db.init_db = MagicMock()
sys.modules['core.database'] = mock_db

mock_models = MagicMock()
sys.modules['core.models'] = mock_models

from services.scanner import (
    get_oast_settings_service,
    get_target_logic_map_service, 
    clean_host_and_port
)

@pytest.mark.asyncio
async def test_get_oast_settings_service():
    """
    Test that get_oast_settings_service returns the expected static dictionary.
    """
    expected = {"enabled": False, "domain": "", "poll_interval": 5}
    result = await get_oast_settings_service()
    assert result == expected

@pytest.mark.asyncio
async def test_get_target_logic_map_service_not_found():
    # Create a mock session that returns None for target lookup
    mock_session = AsyncMock()
    mock_session.get.return_value = None

    # Verify that HTTPException is raised with status 404
    with pytest.raises(HTTPException) as exc_info:
        await get_target_logic_map_service("invalid_target_id", mock_session)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Target not found"

@pytest.mark.asyncio
async def test_get_target_logic_map_service_existing_logic_map():
    # Setup mock target and session
    mock_target = AsyncMock()
    mock_target.logic_map = "existing_map"

    mock_session = AsyncMock()
    mock_session.get.return_value = mock_target

    # Test
    result = await get_target_logic_map_service("target_id", mock_session)

    # Verify it returns existing logic map without generating a new one
    assert result == {"logic_map": "existing_map"}
    mock_session.get.assert_called_once()

@pytest.mark.asyncio
@patch('services.scanner.ai_triage.generate_state_machine')
@patch('core.logic_mapper.aggregate_session_traffic')
async def test_get_target_logic_map_service_generate_new(mock_aggregate, mock_generate):
    # Setup mock target and session
    mock_target = AsyncMock()
    mock_target.logic_map = None  # No existing logic map

    mock_session = AsyncMock()
    mock_session.get.return_value = mock_target

    # Setup mocked functions
    mock_aggregate.return_value = "mock_traffic"
    mock_generate.return_value = "new_generated_map"

    # Test
    result = await get_target_logic_map_service("target_id", mock_session)

    # Verify
    assert result == {"logic_map": "new_generated_map"}
    assert mock_target.logic_map == "new_generated_map"

    mock_session.get.assert_called_once()
    mock_aggregate.assert_called_once_with("target_id")
    mock_generate.assert_called_once_with("mock_traffic")
    mock_session.commit.assert_called_once()

def test_clean_host_and_port_basic():
    host, port = clean_host_and_port("example.com", 80)
    assert host == "example.com"
    assert port == 80

def test_clean_host_and_port_with_port_in_host():
    host, port = clean_host_and_port("example.com:8080", None)
    assert host == "example.com"
    assert port == 8080

def test_clean_host_and_port_override_port():
    host, port = clean_host_and_port("example.com:8080", 9090)
    assert host == "example.com"
    assert port == 9090

def test_clean_host_and_port_with_scheme():
    host, port = clean_host_and_port("https://example.com", 443)
    assert host == "example.com"
    assert port == 443

def test_clean_host_and_port_malformed_port():
    host, port = clean_host_and_port("example.com:notaport", None)
    assert host == "example.com"
    assert port is None

def test_clean_host_and_port_malformed_port_with_provided_port():
    host, port = clean_host_and_port("example.com:notaport", 80)
    assert host == "example.com"
    assert port == 80

def test_clean_host_and_port_ipv6():
    host, port = clean_host_and_port("[2001:db8::1]:8080", None)
    assert host == "2001:db8::1"
    assert port == 8080

def test_clean_host_and_port_strip():
    host, port = clean_host_and_port("  example.com/some/path  ", 80)
    assert host == "example.com"
    assert port == 80