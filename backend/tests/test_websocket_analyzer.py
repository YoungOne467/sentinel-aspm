import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from core.websocket_analyzer import (
    extract_json_schema,
    try_decode_payload,
    parse_payload_data,
    scan_dict_for_secrets,
    monitor_websockets,
    handle_frame,
)
from core.models import WebSocketStream

def test_extract_json_schema():
    data = {
        "username": "user1",
        "details": {
            "age": 30,
            "is_admin": False
        },
        "tags": ["a", "b"]
    }
    schema = extract_json_schema(data)
    assert schema == {
        "username": "str",
        "details": {
            "age": "int",
            "is_admin": "bool"
        },
        "tags": ["str"]
    }

def test_try_decode_payload():
    # Plain text remains plain text
    assert try_decode_payload("hello") == "hello"
    
    # Base64 encoded plain text
    b64_str = "SGVsbG8gV29ybGQ="  # "Hello World"
    assert try_decode_payload(b64_str) == "Hello World"
    
    # Invalid base64 or non-plain-text binary should return the original input
    assert try_decode_payload("SGVsbG8gV29ybGQ") == "SGVsbG8gV29ybGQ"

def test_parse_payload_data():
    # JSON parsing
    raw_json = '{"token": "xyz", "active": true}'
    data, schema = parse_payload_data(raw_json)
    assert data == {"token": "xyz", "active": True}
    assert schema == {"token": "str", "active": "bool"}

    # XML parsing
    raw_xml = '<root><item>test</item></root>'
    data, schema = parse_payload_data(raw_xml)
    assert data == raw_xml
    assert schema == {"type": "xml"}

    # Fallback to plain text
    data, schema = parse_payload_data("plain text")
    assert data == "plain text"
    assert schema is None

def test_scan_dict_for_secrets():
    # Non-sensitive keys
    data = {"name": "Test", "id": 123}
    assert scan_dict_for_secrets(data) is None

    # Sensitive key, unencrypted value
    data = {"user": "admin", "password": "supersecretpassword123"}
    hit = scan_dict_for_secrets(data)
    assert hit == ("password", "supersecretpassword123")

    # Nested check
    data = {"meta": {"details": {"token": "auth_token_value"}}}
    hit = scan_dict_for_secrets(data)
    assert hit == ("token", "auth_token_value")

@pytest.mark.asyncio
@patch("core.database.batch_writer.enqueue")
async def test_handle_frame_pii(mock_enqueue):
    # Mock frame with SSN
    mock_frame = MagicMock()
    mock_frame.payload = "User SSN is 000-12-3456 in the system."

    await handle_frame(mock_frame, "received", "ws://test.local", "target-123")

    # Assert enqueue was called
    assert mock_enqueue.call_count == 1
    stream = mock_enqueue.call_args[0][0]
    assert isinstance(stream, WebSocketStream)
    assert stream.target_id == "target-123"
    assert stream.url == "ws://test.local"
    assert stream.direction == "received"
    assert stream.dlp_finding_type == "PII"
    assert stream.dlp_finding_value == "000-12-3456"
    assert "GDPR" in stream.compliance_tags

@pytest.mark.asyncio
@patch("core.database.batch_writer.enqueue")
async def test_handle_frame_credentials_regex(mock_enqueue):
    # Mock frame with Private Key
    mock_frame = MagicMock()
    mock_frame.payload = "-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQ..."

    await handle_frame(mock_frame, "sent", "ws://test.local", "target-123")

    assert mock_enqueue.call_count == 1
    stream = mock_enqueue.call_args[0][0]
    assert stream.dlp_finding_type == "Credential"
    assert "PCI-DSS" in stream.compliance_tags

def test_monitor_websockets_registration():
    mock_page = MagicMock()
    mock_ws = MagicMock()
    mock_ws.url = "ws://test.local"
    
    # Capture the callbacks registered on mock_page and mock_ws
    page_events = {}
    ws_events = {}

    def page_on(event, cb):
        page_events[event] = cb
    mock_page.on.side_effect = page_on

    def ws_on(event, cb):
        ws_events[event] = cb
    mock_ws.on.side_effect = ws_on

    monitor_websockets(mock_page, "target-123")

    # Verify websocket listener is registered on page
    assert "websocket" in page_events
    
    # Trigger websocket detection
    page_events["websocket"](mock_ws)

    # Verify framesent/framereceived are registered on the websocket object
    assert "framesent" in ws_events
    assert "framereceived" in ws_events
