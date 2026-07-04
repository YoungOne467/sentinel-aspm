import os
import logging
from unittest.mock import patch, MagicMock
from cryptography.fernet import Fernet
from core.encryption_store import EncryptionStore

def test_encryption_store_with_custom_key():
    # Test setting key directly
    key = Fernet.generate_key().decode()
    store = EncryptionStore(key=key)
    
    plaintext = "super secret finding"
    encrypted = store.encrypt_string(plaintext)
    decrypted = store.decrypt_string(encrypted)
    assert decrypted == plaintext
    assert encrypted != plaintext

def test_encryption_store_with_env_key():
    # Test loading key from environment variable
    key = Fernet.generate_key().decode()
    with patch.dict(os.environ, {"SENTINEL_ENCRYPTION_KEY": key}):
        store = EncryptionStore()
        plaintext = "another secret value"
        encrypted = store.encrypt_string(plaintext)
        decrypted = store.decrypt_string(encrypted)
        assert decrypted == plaintext

def test_encryption_store_fallback_random_key_logged(caplog):
    # Test fallback to generating a random key when no env var is present
    with patch.dict(os.environ, {}):
        if "SENTINEL_ENCRYPTION_KEY" in os.environ:
            del os.environ["SENTINEL_ENCRYPTION_KEY"]
        
        with caplog.at_level(logging.INFO):
            store = EncryptionStore()
            
            # Check log message
            assert any("SENTINEL_ENCRYPTION_KEY environment variable not found" in record.message for record in caplog.records)
            
            # Check it still functions correctly
            plaintext = "fallback test string"
            encrypted = store.encrypt_string(plaintext)
            decrypted = store.decrypt_string(encrypted)
            assert decrypted == plaintext

def test_encryption_store_invalid_env_key_logged(caplog):
    # Test loading an invalid key format generates a fallback key and warning
    with patch.dict(os.environ, {"SENTINEL_ENCRYPTION_KEY": "invalid-key"}):
        with caplog.at_level(logging.WARNING):
            store = EncryptionStore()
            
            # Check log message
            assert any("Invalid SENTINEL_ENCRYPTION_KEY format" in record.message for record in caplog.records)
            
            # Check it still functions correctly
            plaintext = "invalid key fallback test string"
            encrypted = store.encrypt_string(plaintext)
            decrypted = store.decrypt_string(encrypted)
            assert decrypted == plaintext
