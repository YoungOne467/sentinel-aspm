import json
import base64
import logging
import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Any, Tuple

from core.database import batch_writer
from core.models import WebSocketStream

logger = logging.getLogger("sentinel.websocket_analyzer")

# Compiled regexes for unencrypted secret detection in JSON values
SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|secret|token|key|auth|credential|private|passwd)", re.IGNORECASE
)

def extract_json_schema(data: Any) -> Any:
    """
    Recursively builds a simplified schema of JSON data by mapping
    values to their python type names (e.g., 'str', 'int', 'float', 'bool').
    """
    if isinstance(data, dict):
        return {k: extract_json_schema(v) for k, v in data.items()}
    elif isinstance(data, list):
        if len(data) > 0:
            return [extract_json_schema(data[0])]
        else:
            return []
    else:
        return type(data).__name__

def try_decode_payload(payload: str) -> str:
    """
    Checks if a payload string is a valid base64-encoded text stream.
    If it decodes cleanly to plain-text, returns the decoded string.
    """
    try:
        # Check if length is a multiple of 4 and characters are alphanumeric + / =
        if len(payload) >= 4 and len(payload) % 4 == 0 and re.match(r"^[A-Za-z0-9+/=]+$", payload):
            decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
            # If the resulting string contains printable characters and is not purely empty/spaces
            if decoded.strip() and all(c.isprintable() or c in "\r\n\t" for c in decoded):
                return decoded
    except Exception:
        pass
    return payload

def parse_payload_data(decoded_str: str) -> Tuple[Any, Any]:
    """
    Parses structural strings (JSON, XML) and extracts data + schema.
    Returns (parsed_data, schema).
    """
    # Try parsing as JSON
    try:
        data = json.loads(decoded_str)
        schema = extract_json_schema(data)
        return data, schema
    except Exception:
        pass

    # Try parsing as XML
    try:
        ET.fromstring(decoded_str)
        return decoded_str, {"type": "xml"}
    except Exception:
        pass

    return decoded_str, None

def scan_dict_for_secrets(d: Any) -> Tuple[str, str] | None:
    """
    Recursively scans a dictionary looking for unencrypted credentials, tokens, or keys.
    Returns (key, value) if a match is found.
    """
    if isinstance(d, dict):
        for k, v in d.items():
            if isinstance(v, str) and v.strip():
                if SENSITIVE_KEY_PATTERN.search(k):
                    # Basic heuristics: check length and ensure it's not a placeholder/bracket/hash
                    # Ignore values starting with common block markers or short empty values
                    v_strip = v.strip()
                    if len(v_strip) >= 4 and not v_strip.startswith(("$", "{", "[")):
                        return k, v_strip
            else:
                res = scan_dict_for_secrets(v)
                if res:
                    return res
    elif isinstance(d, list):
        for item in d:
            res = scan_dict_for_secrets(item)
            if res:
                return res
    return None

async def handle_frame(frame, direction: str, ws_url: str, target_id: str):
    """
    Asynchronously parses a WebSocket frame, performs DLP checks, and queues it to database.
    """
    try:
        raw_payload = frame.payload
        if isinstance(raw_payload, bytes):
            payload_str = raw_payload.decode("utf-8", errors="replace")
        else:
            payload_str = str(raw_payload)

        # 1. Try to decode Base64
        decoded_payload = try_decode_payload(payload_str)

        # 2. Try parsing (JSON, XML) and extract schemas
        parsed_data, schema = parse_payload_data(decoded_payload)

        # 3. Perform DLP scanning using rules imported from core.dlp_parser
        from core.dlp_parser import SSN_REGEX, EMAIL_REGEX, PRIVATE_KEY_REGEX, TOKEN_REGEX, ROUTE_REGEX

        dlp_type = None
        dlp_val = None
        compliance_tags = []

        ssn_match = SSN_REGEX.search(decoded_payload)
        if ssn_match:
            dlp_type = "PII"
            dlp_val = ssn_match.group(0)
            compliance_tags = ["GDPR"]
        else:
            email_match = EMAIL_REGEX.search(decoded_payload)
            if email_match:
                dlp_type = "PII"
                dlp_val = email_match.group(0)
                compliance_tags = ["GDPR"]
            else:
                key_match = PRIVATE_KEY_REGEX.search(decoded_payload)
                if key_match:
                    dlp_type = "Credential"
                    dlp_val = key_match.group(0)
                    compliance_tags = ["PCI-DSS"]
                else:
                    token_match = TOKEN_REGEX.search(decoded_payload)
                    if token_match:
                        dlp_type = "Credential"
                        dlp_val = token_match.group(0)
                        compliance_tags = ["PCI-DSS"]
                    else:
                        route_match = ROUTE_REGEX.search(decoded_payload)
                        if route_match:
                            dlp_type = "Internal URI"
                            dlp_val = route_match.group(1)
                            compliance_tags = []

        # If no regex hit, fallback to checking recursively for unencrypted credentials in JSON keys
        if not dlp_type and (isinstance(parsed_data, dict) or isinstance(parsed_data, list)):
            secret_hit = scan_dict_for_secrets(parsed_data)
            if secret_hit:
                key, val = secret_hit
                dlp_type = "Credential"
                dlp_val = f"{key}={val}"
                compliance_tags = ["PCI-DSS"]

        # 4. Save finding via the micro-batch writer
        stream = WebSocketStream(
            target_id=target_id,
            url=ws_url,
            direction=direction,
            payload=payload_str,
            payload_schema=schema,
            dlp_finding_type=dlp_type,
            dlp_finding_value=dlp_val,
            compliance_tags=compliance_tags,
        )
        await batch_writer.enqueue(stream)

    except Exception as e:
        logger.error("Error handling WebSocket frame: %s", e)

def monitor_websockets(page, target_id: str):
    """
    Attaches event listeners to the Playwright Page context to monitor and log
    WebSocket connections and frames passively.
    """
    logger.info("Initializing WebSocket telemetry hook on page context.")

    def on_websocket(ws):
        ws_url = ws.url
        logger.info("WebSocket connection detected: %s", ws_url)

        # Attach framesent and framereceived event listeners
        ws.on(
            "framesent",
            lambda frame: asyncio.create_task(
                handle_frame(frame, "sent", ws_url, target_id)
            ),
        )
        ws.on(
            "framereceived",
            lambda frame: asyncio.create_task(
                handle_frame(frame, "received", ws_url, target_id)
            ),
        )

    page.on("websocket", on_websocket)
