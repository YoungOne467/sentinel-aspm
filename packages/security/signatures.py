import time
import json
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import redis.asyncio as aioredis

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from packages.execution.interfaces import ExecutionContract

logger = logging.getLogger(__name__)

def canonicalize_contract_payload(contract_data: Dict[str, Any]) -> bytes:
    """
    Creates a stable, deterministic byte representation of all 15 authorization/routing fields.
    """
    critical_data = {
        "contract_id": contract_data.get("contract_id"),
        "execution_id": contract_data.get("execution_id"),
        "tenant_id": contract_data.get("tenant_id"),
        "workspace_id": contract_data.get("workspace_id"),
        "contract_version": contract_data.get("contract_version"),
        "target_node_id": contract_data.get("target_node_id"),
        "scheduler_id": contract_data.get("scheduler_id"),
        "scheduler_version": contract_data.get("scheduler_version"),
        "timestamp": float(contract_data.get("timestamp") or 0.0),
        "expires_at": float(contract_data.get("expires_at") or 0.0),
        "nonce": contract_data.get("nonce"),
        "image": contract_data.get("image"),
        "command": list(contract_data.get("command") or []),
        "env": {k: str(v) for k, v in (contract_data.get("env") or {}).items()},
        "capabilities": sorted(list(contract_data.get("capabilities") or [])),
    }
    return json.dumps(critical_data, sort_keys=True).encode("utf-8")

class ReplayProtectionStore(ABC):
    @abstractmethod
    async def claim(self, tenant_id: str, node_id: str, nonce: str, ttl_seconds: int) -> bool:
        """
        Atomically claims a nonce for the given tenant and node.
        Returns True if the nonce was successfully claimed, False if it was already seen.
        """
        pass

class InMemoryReplayProtectionStore(ReplayProtectionStore):
    def __init__(self):
        self._nonces = {}  # key -> expiry_time
        self._lock = asyncio.Lock()

    async def claim(self, tenant_id: str, node_id: str, nonce: str, ttl_seconds: int) -> bool:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        if not node_id or node_id.strip() == "":
            raise ValueError("node_id must be explicit and non-empty")
        if not nonce or nonce.strip() == "":
            raise ValueError("nonce must be explicit and non-empty")

        key = f"{tenant_id}:{node_id}:{nonce}"
        async with self._lock:
            current_time = time.time()
            # Prune expired keys
            expired_keys = [k for k, exp in self._nonces.items() if current_time >= exp]
            for k in expired_keys:
                del self._nonces[k]

            if key in self._nonces:
                if current_time < self._nonces[key]:
                    return False
            
            self._nonces[key] = current_time + ttl_seconds
            return True

class RedisReplayProtectionStore(ReplayProtectionStore):
    def __init__(self, redis_client=None, redis_url: str = "redis://localhost:6379/0"):
        if redis_client is not None:
            self._client = redis_client
        else:
            self._client = aioredis.from_url(redis_url, decode_responses=True)

    async def claim(self, tenant_id: str, node_id: str, nonce: str, ttl_seconds: int) -> bool:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        if not node_id or node_id.strip() == "":
            raise ValueError("node_id must be explicit and non-empty")
        if not nonce or nonce.strip() == "":
            raise ValueError("nonce must be explicit and non-empty")

        key = f"nonce:{tenant_id}:{node_id}:{nonce}"
        res = await self._client.set(key, "1", ex=ttl_seconds, nx=True)
        return bool(res)

class ContractSigner:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self.private_key = private_key

    def sign_contract(self, contract_data: Dict[str, Any]) -> str:
        payload = canonicalize_contract_payload(contract_data)
        signature_bytes = self.private_key.sign(
            payload,
            ec.ECDSA(hashes.SHA256())
        )
        return signature_bytes.hex()

class ContractVerifier:
    def __init__(
        self,
        trust_roots: Dict[str, ec.EllipticCurvePublicKey],
        replay_store: ReplayProtectionStore,
        clock_skew_tolerance_sec: float = 300.0,
        replay_ttl_sec: int = 3600
    ):
        self.trust_roots = trust_roots
        self.replay_store = replay_store
        self.clock_skew_tolerance_sec = clock_skew_tolerance_sec
        self.replay_ttl_sec = replay_ttl_sec

    async def verify_contract(self, contract: ExecutionContract, current_node_id: str) -> bool:
        """
        Verify the contract against all safety and cryptographic rules.
        """
        if not contract.tenant_id or contract.tenant_id.strip() == "":
            logger.error("Contract validation failed: tenant_id is missing or empty")
            await self._emit_security_alert(contract, "Missing tenant context")
            return False

        if contract.target_node_id != current_node_id:
            logger.error(f"Contract target node mismatch: expected {current_node_id}, got {contract.target_node_id}")
            return False

        if not contract.scheduler_id or contract.scheduler_id not in self.trust_roots:
            logger.error(f"Untrusted scheduler identity: {contract.scheduler_id}")
            await self._emit_security_alert(contract, f"Untrusted scheduler identity: {contract.scheduler_id}")
            return False

        if contract.contract_version != "1.0.0":
            logger.error(f"Unsupported contract version: {contract.contract_version}")
            return False

        current_time = time.time()
        if current_time > contract.expires_at:
            logger.error(f"Contract expired: current time {current_time} > expires_at {contract.expires_at}")
            return False

        if abs(current_time - contract.timestamp) > self.clock_skew_tolerance_sec:
            logger.error(f"Contract timestamp outside allowed skew: timestamp {contract.timestamp}, current {current_time}")
            return False

        public_key = self.trust_roots[contract.scheduler_id]
        contract_dict = {
            "contract_id": contract.contract_id,
            "execution_id": contract.execution_id,
            "tenant_id": contract.tenant_id,
            "workspace_id": contract.workspace_id,
            "contract_version": contract.contract_version,
            "target_node_id": contract.target_node_id,
            "scheduler_id": contract.scheduler_id,
            "scheduler_version": contract.scheduler_version,
            "timestamp": contract.timestamp,
            "expires_at": contract.expires_at,
            "nonce": contract.nonce,
            "image": contract.image,
            "command": contract.command,
            "env": contract.env,
            "capabilities": contract.capabilities,
        }
        payload = canonicalize_contract_payload(contract_dict)
        try:
            sig_bytes = bytes.fromhex(contract.signature)
            public_key.verify(
                sig_bytes,
                payload,
                ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            logger.error(f"Cryptographic signature verification failed: {e}")
            await self._emit_security_alert(contract, f"Invalid signature: {e}")
            return False

        claimed = await self.replay_store.claim(
            tenant_id=contract.tenant_id,
            node_id=current_node_id,
            nonce=contract.nonce,
            ttl_seconds=self.replay_ttl_sec
        )
        if not claimed:
            logger.error(f"Replay protection: nonce {contract.nonce} already claimed")
            await self._emit_security_alert(contract, f"Replay attack detected: duplicate nonce {contract.nonce}")
            return False

        return True

    async def _emit_security_alert(self, contract: ExecutionContract, reason: str):
        try:
            from packages.audit.emitter import audit_emitter
            from packages.audit.events import AuditEvent
            
            class SecurityAlertEvent(AuditEvent):
                pass
                
            await audit_emitter.emit(
                SecurityAlertEvent(
                    name="SecurityAlert",
                    payload={
                        "contract_id": contract.contract_id,
                        "execution_id": contract.execution_id,
                        "tenant_id": contract.tenant_id or "unknown",
                        "workspace_id": contract.workspace_id or "unknown",
                        "reason": reason,
                        "scheduler_id": contract.scheduler_id or "unknown",
                        "node_id": contract.target_node_id or "unknown"
                    }
                ),
                actor="system"
            )
        except Exception as e:
            logger.error(f"Failed to emit security alert: {e}")
