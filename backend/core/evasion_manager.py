import os
import json
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

def get_evasion_settings_path() -> Path:
    configured = os.getenv("SENTINEL_EVASION_SETTINGS_PATH", "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[2] / "scratch" / "evasion_settings.json"

DEFAULT_EVASION_SETTINGS = {
    "custom_headers": {
        "X-Forwarded-For": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1"
    },
    "sqli_strategy": "space_to_comment",
    "xss_strategy": "default_polyglot",
    "lfi_strategy": "double_encoding"
}

_evasion_settings_cache: Dict[str, Any] = None

def load_evasion_settings() -> Dict[str, Any]:
    global _evasion_settings_cache
    if _evasion_settings_cache is not None:
        return _evasion_settings_cache

    path = get_evasion_settings_path()
    if not path.exists():
        _evasion_settings_cache = dict(DEFAULT_EVASION_SETTINGS)
        return _evasion_settings_cache

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        # Merge with defaults to ensure all keys exist
        settings = dict(DEFAULT_EVASION_SETTINGS)
        settings.update(data)
        _evasion_settings_cache = settings
        return _evasion_settings_cache
    except Exception as exc:
        logger.warning("Could not load evasion settings file %s: %s. Using defaults.", path, exc)
        return dict(DEFAULT_EVASION_SETTINGS)

def update_evasion_settings(
    custom_headers: Dict[str, str] = None,
    sqli_strategy: str = None,
    xss_strategy: str = None,
    lfi_strategy: str = None
) -> Dict[str, Any]:
    global _evasion_settings_cache
    settings = load_evasion_settings()

    if custom_headers is not None:
        settings["custom_headers"] = custom_headers
    if sqli_strategy is not None:
        settings["sqli_strategy"] = sqli_strategy
    if xss_strategy is not None:
        settings["xss_strategy"] = xss_strategy
    if lfi_strategy is not None:
        settings["lfi_strategy"] = lfi_strategy

    path = get_evasion_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        _evasion_settings_cache = settings
    except Exception as exc:
        logger.error("Could not write evasion settings file %s: %s", path, exc)

    return settings
