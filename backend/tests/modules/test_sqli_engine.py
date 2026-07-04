import pytest
from modules.sqli_engine import _detect_db_errors

def test_detect_db_errors_with_none():
    """Test that _detect_db_errors raises TypeError when passed None."""
    with pytest.raises(TypeError):
        _detect_db_errors(None)

def test_detect_db_errors_with_bytes():
    """Test that _detect_db_errors raises TypeError when passed bytes."""
    with pytest.raises(TypeError):
        _detect_db_errors(b"malformed byte sequence")
