"""Tests for the plugin_sdk bounded context: signature trust levels, revocation, and unsigned blocking."""

import json
import hashlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.plugin_sdk.registry import (
    SignatureVerifier,
    PluginRegistry,
    TrustLevel,
    SignatureData,
)
from packages.plugin_sdk.interfaces import CapabilityDecision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manifest(plugin_id="test-plugin", capabilities=None, secrets=None, image="alpine:latest"):
    return {
        "id": plugin_id,
        "version": "1.0.0",
        "name": "Test Plugin",
        "runtime": {"image": image},
        "capabilities": capabilities or [],
        "secrets": secrets or [],
    }


def _make_signature_block(trust_level, publisher_key, image_digest, sig_bytes="VALID_OFFICIAL_SIG"):
    return {
        "signature_bytes": sig_bytes,
        "trust_level": trust_level,
        "provenance": {
            "publisher": {"id": "test-publisher", "signing_key": publisher_key},
            "source": {"repository": "https://github.com/sentinel", "commit": "abc123"},
            "build": {"image_digest": image_digest},
        },
    }


# ---------------------------------------------------------------------------
# SignatureVerifier trust level tests
# ---------------------------------------------------------------------------

class TestSignatureVerifier:
    @pytest.mark.asyncio
    async def test_no_signature_returns_local(self):
        """A manifest without a signature block should be classified as LOCAL."""
        verifier = SignatureVerifier()
        manifest = _make_manifest()
        level = await verifier.verify(manifest, None)
        assert level == TrustLevel.LOCAL

    @pytest.mark.asyncio
    async def test_empty_signature_returns_local(self):
        """An empty dict signature block should be LOCAL."""
        verifier = SignatureVerifier()
        manifest = _make_manifest()
        level = await verifier.verify(manifest, {})
        assert level == TrustLevel.LOCAL

    @pytest.mark.asyncio
    async def test_official_trusted_signature(self):
        """A valid Official-level signature with a trusted key should return OFFICIAL."""
        verifier = SignatureVerifier()
        manifest = _make_manifest(image="alpine:latest")
        sig = _make_signature_block(
            trust_level="Official",
            publisher_key="official-sentinel-fingerprint",
            image_digest="alpine:latest",
        )
        level = await verifier.verify(manifest, sig)
        assert level == TrustLevel.OFFICIAL

    @pytest.mark.asyncio
    async def test_untrusted_key_falls_back_to_local(self):
        """A signature with an unrecognized signing key should fall back to LOCAL."""
        verifier = SignatureVerifier()
        manifest = _make_manifest(image="alpine:latest")
        sig = _make_signature_block(
            trust_level="Official",
            publisher_key="unknown-key-fingerprint",
            image_digest="alpine:latest",
        )
        level = await verifier.verify(manifest, sig)
        assert level == TrustLevel.LOCAL

    @pytest.mark.asyncio
    async def test_image_digest_mismatch_returns_local(self):
        """If provenance image digest doesn't match the manifest runtime image, return LOCAL."""
        verifier = SignatureVerifier()
        manifest = _make_manifest(image="alpine:latest")
        sig = _make_signature_block(
            trust_level="Official",
            publisher_key="official-sentinel-fingerprint",
            image_digest="totally-different-image:v2",
        )
        level = await verifier.verify(manifest, sig)
        assert level == TrustLevel.LOCAL

    @pytest.mark.asyncio
    async def test_verified_trust_level(self):
        """A Verified-level signature with a trusted key should return VERIFIED."""
        verifier = SignatureVerifier()
        manifest = _make_manifest(image="scanner:v1")
        sig = _make_signature_block(
            trust_level="Verified",
            publisher_key="official-sentinel-fingerprint",
            image_digest="scanner:v1",
        )
        level = await verifier.verify(manifest, sig)
        assert level == TrustLevel.VERIFIED


# ---------------------------------------------------------------------------
# Trust revocation (PluginRegistry)
# ---------------------------------------------------------------------------

class TestPluginRegistryTrustRevocation:
    @pytest.mark.asyncio
    async def test_community_blocked_by_default(self):
        """Community plugins should be blocked when community_allowed is False (default)."""
        registry = PluginRegistry()
        manifest = _make_manifest(image="community-plugin:latest")
        sig = _make_signature_block(
            trust_level="Community",
            publisher_key="official-sentinel-fingerprint",
            image_digest="community-plugin:latest",
        )
        allowed = await registry.evaluate_trust(manifest, sig)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_community_allowed_when_enabled(self):
        """Community plugins should be allowed when community_allowed is True."""
        registry = PluginRegistry()
        registry.community_allowed = True
        manifest = _make_manifest(image="community-plugin:latest")
        sig = _make_signature_block(
            trust_level="Community",
            publisher_key="official-sentinel-fingerprint",
            image_digest="community-plugin:latest",
        )
        allowed = await registry.evaluate_trust(manifest, sig)
        assert allowed is True

    @pytest.mark.asyncio
    async def test_local_blocked_by_default(self):
        """Local (unsigned) plugins should be blocked by default."""
        registry = PluginRegistry()
        manifest = _make_manifest()
        allowed = await registry.evaluate_trust(manifest, None)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_local_allowed_when_enabled(self):
        """Local plugins should be allowed when local_allowed is True."""
        registry = PluginRegistry()
        registry.local_allowed = True
        manifest = _make_manifest()
        allowed = await registry.evaluate_trust(manifest, None)
        assert allowed is True


# ---------------------------------------------------------------------------
# Unsigned plugin blocking via DefaultCapabilityResolver
# ---------------------------------------------------------------------------

class TestUnsignedPluginBlocking:
    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_unsigned_plugin_denied_by_resolver(self, mock_audit):
        """The DefaultCapabilityResolver should deny execution for unsigned plugins."""
        mock_audit.emit = AsyncMock()

        from packages.plugin_sdk.resolver import DefaultCapabilityResolver

        resolver = DefaultCapabilityResolver()
        # PluginRegistry defaults: local_allowed=False
        manifest = _make_manifest(capabilities=["network:external"])
        decision = await resolver.validate(
            requested_capabilities=["network:external"],
            plugin_id="unsigned-plugin",
            manifest_data=manifest,
            signature_block=None,  # unsigned
        )
        assert decision.allowed is False
        assert "trust" in decision.reason.lower()

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_disallowed_capability_denied(self, mock_audit):
        """Requesting capabilities not in the global allowlist should be denied even for trusted plugins."""
        mock_audit.emit = AsyncMock()

        from packages.plugin_sdk.resolver import DefaultCapabilityResolver

        resolver = DefaultCapabilityResolver()
        resolver.registry.local_allowed = True  # Allow LOCAL trust level

        manifest = _make_manifest(capabilities=["kernel:escalate"])
        decision = await resolver.validate(
            requested_capabilities=["kernel:escalate"],
            plugin_id="evil-plugin",
            manifest_data=manifest,
            signature_block=None,
        )
        assert decision.allowed is False
        assert "kernel:escalate" in decision.denied_capabilities
