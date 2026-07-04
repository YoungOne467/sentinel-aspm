import pytest
from modules.xss_engine import _canary

def test_canary_default_prefix():
    """Test that _canary generates a string with the default prefix 'aXs' and correct length."""
    result = _canary()
    assert result.startswith("aXs")
    assert len(result) == len("aXs") + 8

def test_canary_empty_prefix():
    """Test that _canary generates a string with an empty prefix and correct length."""
    result = _canary(prefix="")
    assert not result.startswith("aXs")
    assert len(result) == 8  # Just the uuid hex

def test_canary_custom_prefix():
    """Test that _canary generates a string with a custom prefix and correct length."""
    custom_prefix = "testPref"
    result = _canary(prefix=custom_prefix)
    assert result.startswith(custom_prefix)
    assert len(result) == len(custom_prefix) + 8

def test_canary_uniqueness():
    """Test that consecutive calls to _canary generate unique strings."""
    results = [_canary() for _ in range(100)]
    assert len(set(results)) == 100