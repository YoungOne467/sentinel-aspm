import time
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import ec

from packages.execution.interfaces import ExecutionContract
from packages.security.signatures import (
    InMemoryReplayProtectionStore,
    ContractSigner,
    ContractVerifier,
    canonicalize_contract_payload
)

class TestReplayStore:
    @pytest.mark.asyncio
    async def test_atomic_claim_success_and_replay_rejection(self):
        store = InMemoryReplayProtectionStore()
        # First claim succeeds
        res1 = await store.claim("tenant1", "node1", "nonce1", 10)
        assert res1 is True

        # Second claim with same params fails
        res2 = await store.claim("tenant1", "node1", "nonce1", 10)
        assert res2 is False

    @pytest.mark.asyncio
    async def test_namespacing_tenant_and_node(self):
        store = InMemoryReplayProtectionStore()
        # Claim for tenant1/node1
        assert await store.claim("tenant1", "node1", "nonce1", 10) is True

        # Different tenant, same node/nonce succeeds
        assert await store.claim("tenant2", "node1", "nonce1", 10) is True

        # Same tenant, different node/nonce succeeds
        assert await store.claim("tenant1", "node2", "nonce1", 10) is True

    @pytest.mark.asyncio
    async def test_claim_ttl_expiration(self):
        store = InMemoryReplayProtectionStore()
        with patch("time.time") as mock_time:
            mock_time.return_value = 1000.0
            assert await store.claim("t1", "n1", "nonce1", 5) is True
            # Replay immediately fails
            assert await store.claim("t1", "n1", "nonce1", 5) is False

            # Advance time past TTL (5 seconds)
            mock_time.return_value = 1006.0
            # Claim succeeds again
            assert await store.claim("t1", "n1", "nonce1", 5) is True

    @pytest.mark.asyncio
    async def test_explicit_tenant_and_node_checks(self):
        store = InMemoryReplayProtectionStore()
        with pytest.raises(ValueError):
            await store.claim("", "node1", "nonce1", 10)
        with pytest.raises(ValueError):
            await store.claim("tenant1", "", "nonce1", 10)
        with pytest.raises(ValueError):
            await store.claim("tenant1", "node1", "", 10)

class TestContractVerifier:
    @pytest.fixture
    def keypair(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        return priv, pub

    @pytest.fixture
    def verifier(self, keypair):
        _, pub = keypair
        trust_roots = {"sched1": pub}
        replay_store = InMemoryReplayProtectionStore()
        return ContractVerifier(trust_roots, replay_store)

    def _make_valid_contract_data(self, signer, scheduler_id="sched1"):
        now = time.time()
        contract_data = {
            "contract_id": "c1",
            "execution_id": "e1",
            "tenant_id": "tenant-a",
            "workspace_id": "ws-a",
            "contract_version": "1.0.0",
            "target_node_id": "node-a",
            "scheduler_id": scheduler_id,
            "scheduler_version": "1.0.0",
            "timestamp": now,
            "expires_at": now + 60.0,
            "nonce": "unique-nonce",
            "image": "alpine:latest",
            "command": ["echo", "hello"],
            "env": {"FOO": "bar"},
            "capabilities": ["filesystem:read"],
        }
        sig = signer.sign_contract(contract_data)
        contract_data["signature"] = sig
        return contract_data

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_valid_contract_passes(self, mock_audit, verifier, keypair):
        mock_audit.emit = AsyncMock()
        priv, _ = keypair
        signer = ContractSigner(priv)
        data = self._make_valid_contract_data(signer)
        contract = ExecutionContract(**data)
        
        valid = await verifier.verify_contract(contract, "node-a")
        assert valid is True

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_unsigned_contract_rejection(self, mock_audit, verifier):
        mock_audit.emit = AsyncMock()
        now = time.time()
        # signature is garbage hex
        contract = ExecutionContract(
            contract_id="c1", execution_id="e1", tenant_id="tenant-a", workspace_id="ws-a",
            contract_version="1.0.0", target_node_id="node-a", scheduler_id="sched1",
            scheduler_version="1.0.0", timestamp=now, expires_at=now+60.0, nonce="n1",
            signature="deadbeef", image="alpine", command=[], env={}, capabilities=[]
        )
        valid = await verifier.verify_contract(contract, "node-a")
        assert valid is False
        mock_audit.emit.assert_called_once()
        assert "Invalid signature" in mock_audit.emit.call_args[0][0].payload["reason"]

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_invalid_signature_different_key(self, mock_audit, verifier):
        mock_audit.emit = AsyncMock()
        # Sign with another key not in trust roots
        other_priv = ec.generate_private_key(ec.SECP256R1())
        signer = ContractSigner(other_priv)
        data = self._make_valid_contract_data(signer)
        contract = ExecutionContract(**data)

        # Verifier should reject because signature won't match key of 'sched1'
        valid = await verifier.verify_contract(contract, "node-a")
        assert valid is False
        mock_audit.emit.assert_called_once()

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_tampered_field_rejection(self, mock_audit, verifier, keypair):
        mock_audit.emit = AsyncMock()
        priv, _ = keypair
        signer = ContractSigner(priv)
        data = self._make_valid_contract_data(signer)
        # Modify capabilities after signing
        data["capabilities"] = ["filesystem:write", "network:external"]
        contract = ExecutionContract(**data)

        valid = await verifier.verify_contract(contract, "node-a")
        assert valid is False

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_nonce_replay_rejection(self, mock_audit, verifier, keypair):
        mock_audit.emit = AsyncMock()
        priv, _ = keypair
        signer = ContractSigner(priv)
        data = self._make_valid_contract_data(signer)
        contract = ExecutionContract(**data)

        # First verify works
        assert await verifier.verify_contract(contract, "node-a") is True
        # Second verify with same contract (nonce) fails
        assert await verifier.verify_contract(contract, "node-a") is False
        assert mock_audit.emit.call_count == 1
        assert "Replay attack detected" in mock_audit.emit.call_args[0][0].payload["reason"]

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_expired_contract_rejection(self, mock_audit, verifier, keypair):
        mock_audit.emit = AsyncMock()
        priv, _ = keypair
        signer = ContractSigner(priv)
        data = self._make_valid_contract_data(signer)
        # Set expires_at in the past
        data["expires_at"] = time.time() - 10.0
        # Re-sign to make signature valid but expired
        data["signature"] = signer.sign_contract(data)
        contract = ExecutionContract(**data)

        valid = await verifier.verify_contract(contract, "node-a")
        assert valid is False

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_scheduler_identity_rejection(self, mock_audit, verifier, keypair):
        mock_audit.emit = AsyncMock()
        priv, _ = keypair
        signer = ContractSigner(priv)
        # Use an unknown scheduler_id
        data = self._make_valid_contract_data(signer, scheduler_id="unknown-sched")
        contract = ExecutionContract(**data)

        valid = await verifier.verify_contract(contract, "node-a")
        assert valid is False
        assert mock_audit.emit.call_count == 1
        assert "Untrusted scheduler identity" in mock_audit.emit.call_args[0][0].payload["reason"]

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_node_target_mismatch_rejection(self, mock_audit, verifier, keypair):
        mock_audit.emit = AsyncMock()
        priv, _ = keypair
        signer = ContractSigner(priv)
        data = self._make_valid_contract_data(signer)
        contract = ExecutionContract(**data)

        # Verifier runs on "node-b", but contract target is "node-a"
        valid = await verifier.verify_contract(contract, "node-b")
        assert valid is False

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.audit_emitter", new_callable=MagicMock)
    async def test_missing_tenant_id_rejection(self, mock_audit, verifier, keypair):
        mock_audit.emit = AsyncMock()
        priv, _ = keypair
        signer = ContractSigner(priv)
        data = self._make_valid_contract_data(signer)
        data["tenant_id"] = ""
        # Re-sign
        data["signature"] = signer.sign_contract(data)
        contract = ExecutionContract(**data)

        valid = await verifier.verify_contract(contract, "node-a")
        assert valid is False
        assert mock_audit.emit.call_count == 1
        assert "Missing tenant context" in mock_audit.emit.call_args[0][0].payload["reason"]
