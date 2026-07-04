import os
import sys
import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

# Add backend directory to path if needed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.ollama_helper import resolve_ollama_model, resolve_ollama_model_sync


# ──────────────────────────────────────────────────────────────────────────────
# 1. Tests for Model Resolution (ollama_helper — still used by other modules)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@patch("core.ollama_helper.fetch_ollama_tags")
async def test_resolve_ollama_model_async_fallbacks(mock_fetch_tags):
    """Test async model resolution behaves correctly under various tag matches."""
    preferred = "hf.co/Melvin56/Phi-4-mini-instruct"
    fallback = "hf.co/mahdisml/Huihui-Qwen3-4B-Instruct-2507-abliterated-Q4_K_M-GGUF:Q4_K_M"

    # Case A: Exact match on preferred
    mock_fetch_tags.return_value = [preferred, "other-model:latest"]
    res = await resolve_ollama_model(preferred, fallback)
    assert res == preferred

    # Case B: Substring match on preferred (case-insensitive)
    mock_fetch_tags.return_value = ["phi-4-mini-instruct", "some-other"]
    res = await resolve_ollama_model(preferred, fallback)
    assert res == "phi-4-mini-instruct"

    # Case C: Preferred missing, exact match on fallback
    mock_fetch_tags.return_value = [fallback, "other-model"]
    res = await resolve_ollama_model(preferred, fallback)
    assert res == fallback

    # Case D: Preferred missing, substring match on fallback
    mock_fetch_tags.return_value = ["huihui-qwen3-4b-instruct", "other-model"]
    res = await resolve_ollama_model(preferred, fallback)
    assert res == "huihui-qwen3-4b-instruct"

    # Case E: Neither found: default to preferred
    mock_fetch_tags.return_value = ["random-model"]
    res = await resolve_ollama_model(preferred, fallback)
    assert res == preferred


@patch("core.ollama_helper.fetch_ollama_tags_sync")
def test_resolve_ollama_model_sync_fallbacks(mock_fetch_tags_sync):
    """Test sync model resolution behaves correctly under various tag matches."""
    preferred = "hf.co/Melvin56/Phi-4-mini-instruct"
    fallback = "hf.co/mahdisml/Huihui-Qwen3-4B-Instruct-2507-abliterated-Q4_K_M-GGUF:Q4_K_M"

    # Case A: Exact match on preferred
    mock_fetch_tags_sync.return_value = [preferred, "other-model:latest"]
    res = resolve_ollama_model_sync(preferred, fallback)
    assert res == preferred

    # Case B: Substring match on preferred
    mock_fetch_tags_sync.return_value = ["phi-4-mini-instruct"]
    res = resolve_ollama_model_sync(preferred, fallback)
    assert res == "phi-4-mini-instruct"

    # Case C: Fallback match
    mock_fetch_tags_sync.return_value = [fallback]
    res = resolve_ollama_model_sync(preferred, fallback)
    assert res == fallback

    # Case D: Neither found -> preferred
    mock_fetch_tags_sync.return_value = ["different-model"]
    res = resolve_ollama_model_sync(preferred, fallback)
    assert res == preferred


# ──────────────────────────────────────────────────────────────────────────────
# 2. Tests for Hardcoded Model Enforcement
# ──────────────────────────────────────────────────────────────────────────────

def test_ai_triage_uses_hardcoded_model():
    """Verify AITriageEngine uses the hardcoded 4B model, not env vars."""
    from core.ai_triage import AITriageEngine, HARDCODED_MODEL
    engine = AITriageEngine()
    assert engine._model == HARDCODED_MODEL
    assert engine._model == "hf.co/Melvin56/Phi-4-mini-instruct-abliterated-GGUF:Q4_K_M"


def test_offline_ai_config_uses_hardcoded_model():
    """Verify OfflineAIConfig defaults to the hardcoded 4B model."""
    from offline_ai_processor import OfflineAIConfig
    config = OfflineAIConfig()
    assert config.model == "hf.co/Melvin56/Phi-4-mini-instruct-abliterated-GGUF:Q4_K_M"


def test_template_generator_uses_hardcoded_model():
    """Verify template_generator.OLLAMA_MODEL is the hardcoded 4B model."""
    from core.template_generator import OLLAMA_MODEL
    assert OLLAMA_MODEL == "hf.co/Melvin56/Phi-4-mini-instruct-abliterated-GGUF:Q4_K_M"


# ──────────────────────────────────────────────────────────────────────────────
# 3. Tests for Circuit Breaker
# ──────────────────────────────────────────────────────────────────────────────

def test_circuit_breaker_opens_after_threshold():
    """Verify circuit breaker opens after 3 consecutive failures."""
    from core.ai_triage import CircuitBreaker
    cb = CircuitBreaker(threshold=3, cooldown=60.0)

    assert cb.state == "CLOSED"
    assert cb.allow_request() is True

    cb.record_failure()
    assert cb.state == "CLOSED"  # 1 strike
    cb.record_failure()
    assert cb.state == "CLOSED"  # 2 strikes
    cb.record_failure()
    assert cb.state == "OPEN"    # 3 strikes — open
    assert cb.allow_request() is False


def test_circuit_breaker_resets_on_success():
    """Verify a success resets the circuit breaker to CLOSED."""
    from core.ai_triage import CircuitBreaker
    cb = CircuitBreaker(threshold=3, cooldown=60.0)

    cb.record_failure()
    cb.record_failure()
    cb.record_success()  # Reset before reaching threshold
    assert cb.state == "CLOSED"
    assert cb.allow_request() is True

    # Verify counter was reset
    cb.record_failure()
    assert cb.state == "CLOSED"  # Only 1 failure since reset


def test_circuit_breaker_half_open_transition():
    """Verify circuit breaker transitions OPEN -> HALF_OPEN after cooldown."""
    import time
    from core.ai_triage import CircuitBreaker
    cb = CircuitBreaker(threshold=1, cooldown=0.1)  # Very short cooldown for test

    cb.record_failure()  # Opens immediately (threshold=1)
    assert cb.state == "OPEN"
    assert cb.allow_request() is False

    time.sleep(0.15)  # Wait for cooldown
    assert cb.state == "HALF_OPEN"
    assert cb.allow_request() is True  # One probe allowed


def test_memory_optimizer_not_importable():
    """Verify that core.memory_optimizer has been deleted and cannot be imported."""
    with pytest.raises(ImportError):
        import importlib
        importlib.import_module("core.memory_optimizer")
