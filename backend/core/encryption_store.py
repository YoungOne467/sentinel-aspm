import os
import json
import logging
from cryptography.fernet import Fernet
from typing import Dict, Any

logger = logging.getLogger(__name__)

class EncryptionStore:
    def __init__(self, key: str = None):
        if key:
            self.fernet = Fernet(key.encode())
        else:
            # Try to get encryption key from environment variable
            env_key = os.environ.get("SENTINEL_ENCRYPTION_KEY")
            if env_key:
                # Ensure it is a valid 32-byte url-safe base64 key
                try:
                    self.fernet = Fernet(env_key.encode())
                except Exception:
                    # In case of invalid key format, generate a fallback key
                    logger.warning("Invalid SENTINEL_ENCRYPTION_KEY format. Generating a random fallback key.")
                    self.fernet = Fernet(Fernet.generate_key())
            else:
                # Fallback to generating a random key
                logger.info("SENTINEL_ENCRYPTION_KEY environment variable not found. Generating a random dev key.")
                self.fernet = Fernet(Fernet.generate_key())

    def encrypt_finding(self, finding: Dict[str, Any]) -> str:
        """Encrypts a finding dictionary into a base64 string."""
        data = json.dumps(finding).encode()
        return self.fernet.encrypt(data).decode()

    def decrypt_finding(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypts a finding string back into a dictionary."""
        data = self.fernet.decrypt(encrypted_data.encode())
        return json.loads(data.decode())

    def encrypt_string(self, text: str) -> str:
        """Encrypts a string value."""
        if not text:
            return ""
        return self.fernet.encrypt(text.encode()).decode()

    def decrypt_string(self, cipher_text: str) -> str:
        """Decrypts a cipher text string."""
        if not cipher_text:
            return ""
        try:
            return self.fernet.decrypt(cipher_text.encode()).decode()
        except Exception:
            # Return original text if decryption fails (e.g. key changed or unencrypted)
            return cipher_text

encryption_store = EncryptionStore()

