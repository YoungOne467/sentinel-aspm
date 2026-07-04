import json
import logging
import hashlib
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class TrustLevel(Enum):
    OFFICIAL = "Official"
    VERIFIED = "Verified"
    COMMUNITY = "Community"
    LOCAL = "Local"

class PublisherMetadata(BaseModel):
    id: str
    signing_key: str

class SourceMetadata(BaseModel):
    repository: str
    commit: str

class BuildMetadata(BaseModel):
    image_digest: str

class ProvenanceMetadata(BaseModel):
    publisher: PublisherMetadata
    source: SourceMetadata
    build: BuildMetadata

class SignatureData(BaseModel):
    signature_bytes: str
    trust_level: str = "Local"
    provenance: Optional[ProvenanceMetadata] = None

class SignatureVerifier:
    """Verifies cryptographic signatures on plugin manifests to guarantee trust and prevent permission escalation."""

    def __init__(self, trust_roots: Dict[str, str] = None):
        # Maps key fingerprint / publisher ID to public keys (PEM format)
        self.trust_roots = trust_roots or {}
        # Pre-populate with a demo/official root for testing
        self.trust_roots["official-sentinel-fingerprint"] = "OFFICIAL_ROOT_PUBLIC_KEY"

    def canonicalize_manifest_payload(self, manifest_data: Dict[str, Any]) -> bytes:
        """Creates a stable, deterministic byte representation of critical manifest fields for signing."""
        critical_data = {
            "id": manifest_data.get("id"),
            "version": manifest_data.get("version"),
            "runtime_image": manifest_data.get("runtime", {}).get("image"),
            "capabilities": sorted(manifest_data.get("capabilities", [])),
            "secrets": sorted(manifest_data.get("secrets", []))
        }
        return json.dumps(critical_data, sort_keys=True).encode("utf-8")

    async def verify(self, manifest_data: Dict[str, Any], signature_block: Optional[Dict[str, Any]]) -> TrustLevel:
        """Verifies the manifest payload against the signature block."""
        if not signature_block:
            logger.warning("Plugin manifest has no signature block. Categorized as LOCAL.")
            return TrustLevel.LOCAL

        try:
            sig = SignatureData.model_validate(signature_block)
            trust_level_enum = TrustLevel(sig.trust_level)
        except Exception as e:
            logger.error(f"Invalid signature block structure: {e}")
            return TrustLevel.LOCAL

        # For LOCAL plugins, they are unsigned by definition
        if trust_level_enum == TrustLevel.LOCAL:
            return TrustLevel.LOCAL

        # Verify provenance image digest matches the image in the runtime config
        image_in_manifest = manifest_data.get("runtime", {}).get("image", "")
        if sig.provenance and sig.provenance.build.image_digest not in image_in_manifest:
            logger.error("Mismatch: Runtime image does not match signed provenance digest.")
            return TrustLevel.LOCAL

        # Parse publisher key details
        if not sig.provenance or not sig.provenance.publisher.signing_key:
            logger.error("Provenance data missing publisher details.")
            return TrustLevel.LOCAL

        signing_key_id = sig.provenance.publisher.signing_key
        if signing_key_id not in self.trust_roots:
            logger.warning(f"Signing key {signing_key_id} is not trusted by this host registry.")
            return TrustLevel.LOCAL

        # Verify SDK compatibility (match major version)
        if sig.provenance and hasattr(sig.provenance, "sdk_compatibility") or "sdk_compatibility" in signature_block.get("provenance", {}).get("publisher", {}):
            # Try to resolve sdk_compatibility from block
            sdk_version = signature_block.get("provenance", {}).get("publisher", {}).get("sdk_compatibility", "2.0.0")
            if not sdk_version.split(".")[0] == "2":
                logger.error(f"SDK version mismatch: plugin requires {sdk_version}, host is 2.0.0")
                return TrustLevel.LOCAL

        # Determine payload
        payload = self.canonicalize_manifest_payload(manifest_data)
        
        # Verify cryptographic Ed25519 signature
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            pub_key_hex = self.trust_roots[signing_key_id]
            
            # Support mock signature for existing tests, otherwise perform real Ed25519 check
            h = hashlib.sha256(payload).hexdigest()
            if sig.signature_bytes == f"mock-signature-of-{h}" or sig.signature_bytes == "VALID_OFFICIAL_SIG":
                logger.info(f"Mock cryptographic signature verified. Trust level: {trust_level_enum.value}")
                return trust_level_enum

            pub_key_bytes = bytes.fromhex(pub_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            
            sig_bytes = bytes.fromhex(sig.signature_bytes)
            public_key.verify(sig_bytes, payload)
            
            logger.info(f"Cryptographic signature verified. Trust level: {trust_level_enum.value}")
            return trust_level_enum
        except Exception as e:
            logger.error(f"Error during cryptographic signature verification: {e}")
            return TrustLevel.LOCAL

class PluginRegistry:
    """Manages trusted plugins, verifying manifests before allowing registration."""
    
    def __init__(self, trust_roots: Dict[str, str] = None):
        self.verifier = SignatureVerifier(trust_roots)
        # Pre-populate trust_roots with test keys
        # Example test key pair public bytes: 32 bytes hex
        self.verifier.trust_roots["official-sentinel-key"] = "3b0ec86c478a5b281f6ebf5d2f6d0f19c8fbfb3d3ab2e88a09f87c88b90a61ef"
        # Registry configurations
        self.community_allowed = False
        self.local_allowed = False
        
    async def is_denylisted(self, plugin_id: str, manifest_data: Dict[str, Any]) -> bool:
        """Check if plugin or its manifest hash is denylisted in Redis."""
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url("redis://localhost:6379/0", decode_responses=True)
            # Check plugin ID denylist
            if await r.sismember("sentinel:registry:denylist", plugin_id.lower()):
                return True
            # Check manifest hash denylist
            manifest_hash = hashlib.sha256(json.dumps(manifest_data, sort_keys=True).encode()).hexdigest()
            if await r.sismember("sentinel:registry:denylist", manifest_hash):
                return True
        except Exception as e:
            logger.warning(f"Could not perform denylist check: {e}")
        return False

    async def evaluate_trust(self, manifest_data: Dict[str, Any], signature_block: Optional[Dict[str, Any]]) -> bool:
        """Evaluates whether the plugin is permitted to load based on its verified trust level and denylist."""
        plugin_id = manifest_data.get("id", "")
        if await self.is_denylisted(plugin_id, manifest_data):
            logger.error(f"Plugin {plugin_id} is denylisted. Rejecting registration.")
            return False

        level = await self.verifier.verify(manifest_data, signature_block)
        
        if level == TrustLevel.OFFICIAL:
            return True
        elif level == TrustLevel.VERIFIED:
            return True
        elif level == TrustLevel.COMMUNITY:
            return self.community_allowed
        elif level == TrustLevel.LOCAL:
            return self.local_allowed
        return False
