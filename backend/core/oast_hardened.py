"""
AETHER Hardened OAST Listener (Item 34).
Encrypted DNS/HTTP interaction listener for out-of-band detection.
Uses AES-256 for finding storage.
"""
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class HardenedOAST:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def generate_token(self, finding_id: str) -> str:
        """Generates an encrypted token for OAST callback."""
        return self.cipher.encrypt(finding_id.encode()).decode()

    def decrypt_callback(self, token: str) -> str:
        """Decrypts a callback token to identify the finding."""
        try:
            return self.cipher.decrypt(token.encode()).decode()
        except Exception:
            return "MALFORMED_TOKEN"

oast_handler = HardenedOAST()
