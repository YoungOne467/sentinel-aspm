import time
import json
import logging
import asyncio
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import redis.asyncio as aioredis

from packages.execution.isolation import IsolationLevel
from packages.audit.interfaces import AuditEvent
from packages.audit.emitter import audit_emitter

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class GenericFleetEvent(AuditEvent):
    pass

@dataclass
class ExecutionReservation:
    reservation_id: str
    execution_id: str
    node_id: str
    scheduler_id: str
    tenant_id: str
    memory: int
    cpu: float
    created_at: float
    expires_at: float
    status: str = "pending"  # "pending" | "claimed" | "released" | "expired"

class ReservationStore(ABC):
    @abstractmethod
    async def create_reservation(
        self,
        reservation_id: str,
        execution_id: str,
        node_id: str,
        scheduler_id: str,
        tenant_id: str,
        memory: int,
        cpu: float,
        ttl_seconds: int
    ) -> bool:
        """
        Atomically creates a pending reservation.
        """
        pass

    @abstractmethod
    async def claim_reservation(self, execution_id: str) -> bool:
        """
        Atomically transitions the reservation status to claimed.
        """
        pass

    @abstractmethod
    async def release_reservation(self, execution_id: str, reason: str = "Released by scheduler") -> bool:
        """
        Atomically transitions the reservation status to released.
        """
        pass

    @abstractmethod
    async def get_node_pending_reservations(self, node_id: str) -> List[ExecutionReservation]:
        """
        Returns all active pending reservations on a node that have not expired.
        """
        pass

    @abstractmethod
    async def get_reservation(self, execution_id: str) -> Optional[ExecutionReservation]:
        """
        Retrieves a reservation by execution ID.
        """
        pass

    @abstractmethod
    async def cleanup_expired_reservations(self) -> List[str]:
        """
        Cleans up expired pending reservations and emits ReservationExpired events.
        Returns the list of execution IDs that expired.
        """
        pass

class InMemoryReservationStore(ReservationStore):
    def __init__(self):
        self._reservations: Dict[str, ExecutionReservation] = {}
        self._lock = asyncio.Lock()

    async def _emit_audit_event(self, name: str, payload: Dict[str, Any]):
        try:
            await audit_emitter.emit(
                GenericFleetEvent(name=name, payload=payload),
                actor="system"
            )
        except Exception as e:
            logger.error(f"Failed to emit fleet audit event {name}: {e}")

    async def create_reservation(
        self,
        reservation_id: str,
        execution_id: str,
        node_id: str,
        scheduler_id: str,
        tenant_id: str,
        memory: int,
        cpu: float,
        ttl_seconds: int
    ) -> bool:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        if not node_id or node_id.strip() == "":
            raise ValueError("node_id must be explicit and non-empty")

        async with self._lock:
            # 1. Cleanup expired first
            await self._cleanup_expired_internal()

            # 2. Prevent scheduler from holding more than one active reservation for the same execution
            existing = self._reservations.get(execution_id)
            if existing and existing.status == "pending":
                logger.warning(f"Active reservation already exists for execution {execution_id}")
                return False

            now = time.time()
            res = ExecutionReservation(
                reservation_id=reservation_id,
                execution_id=execution_id,
                node_id=node_id,
                scheduler_id=scheduler_id,
                tenant_id=tenant_id,
                memory=memory,
                cpu=cpu,
                created_at=now,
                expires_at=now + ttl_seconds,
                status="pending"
            )
            self._reservations[execution_id] = res
            return True

    async def claim_reservation(self, execution_id: str) -> bool:
        async with self._lock:
            await self._cleanup_expired_internal()
            if execution_id not in self._reservations:
                return False
            res = self._reservations[execution_id]
            if res.status != "pending" or time.time() >= res.expires_at:
                return False
            res.status = "claimed"
            return True

    async def release_reservation(self, execution_id: str, reason: str = "Released by scheduler") -> bool:
        async with self._lock:
            if execution_id not in self._reservations:
                return False
            res = self._reservations[execution_id]
            if res.status == "pending":
                res.status = "released"
                await self._emit_audit_event(
                    "ReservationReleased",
                    {
                        "execution_id": execution_id,
                        "reservation_id": res.reservation_id,
                        "node_id": res.node_id,
                        "tenant_id": res.tenant_id,
                        "scheduler_id": res.scheduler_id,
                        "reason": reason
                    }
                )
                return True
            return False

    async def get_node_pending_reservations(self, node_id: str) -> List[ExecutionReservation]:
        now = time.time()
        pending = []
        async with self._lock:
            for res in self._reservations.values():
                if res.node_id == node_id and res.status == "pending" and now < res.expires_at:
                    pending.append(res)
        return pending

    async def get_reservation(self, execution_id: str) -> Optional[ExecutionReservation]:
        async with self._lock:
            return self._reservations.get(execution_id)

    async def cleanup_expired_reservations(self) -> List[str]:
        async with self._lock:
            return await self._cleanup_expired_internal()

    async def _cleanup_expired_internal(self) -> List[str]:
        now = time.time()
        expired = []
        for exec_id, res in list(self._reservations.items()):
            if res.status == "pending" and now >= res.expires_at:
                res.status = "expired"
                expired.append(exec_id)
                await self._emit_audit_event(
                    "ReservationExpired",
                    {
                        "execution_id": exec_id,
                        "reservation_id": res.reservation_id,
                        "node_id": res.node_id,
                        "tenant_id": res.tenant_id,
                        "scheduler_id": res.scheduler_id,
                        "reason": "TTL expired"
                    }
                )
        return expired

class RedisReservationStore(ReservationStore):
    def __init__(self, redis_client=None, redis_url: str = "redis://localhost:6379/0"):
        if redis_client is not None:
            self._client = redis_client
        else:
            self._client = aioredis.from_url(redis_url, decode_responses=True)

    async def _emit_audit_event(self, name: str, payload: Dict[str, Any]):
        try:
            await audit_emitter.emit(
                GenericFleetEvent(name=name, payload=payload),
                actor="system"
            )
        except Exception as e:
            logger.error(f"Failed to emit fleet audit event {name}: {e}")

    def _to_dict(self, res: ExecutionReservation) -> Dict[str, Any]:
        return {
            "reservation_id": res.reservation_id,
            "execution_id": res.execution_id,
            "node_id": res.node_id,
            "scheduler_id": res.scheduler_id,
            "tenant_id": res.tenant_id,
            "memory": res.memory,
            "cpu": res.cpu,
            "created_at": res.created_at,
            "expires_at": res.expires_at,
            "status": res.status
        }

    def _from_dict(self, d: Dict[str, Any]) -> ExecutionReservation:
        return ExecutionReservation(
            reservation_id=d["reservation_id"],
            execution_id=d["execution_id"],
            node_id=d["node_id"],
            scheduler_id=d["scheduler_id"],
            tenant_id=d["tenant_id"],
            memory=d["memory"],
            cpu=d["cpu"],
            created_at=d["created_at"],
            expires_at=d["expires_at"],
            status=d["status"]
        )

    async def create_reservation(
        self,
        reservation_id: str,
        execution_id: str,
        node_id: str,
        scheduler_id: str,
        tenant_id: str,
        memory: int,
        cpu: float,
        ttl_seconds: int
    ) -> bool:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        if not node_id or node_id.strip() == "":
            raise ValueError("node_id must be explicit and non-empty")

        key = f"reservation:{execution_id}"
        # Atomic SET NX
        now = time.time()
        res = ExecutionReservation(
            reservation_id=reservation_id,
            execution_id=execution_id,
            node_id=node_id,
            scheduler_id=scheduler_id,
            tenant_id=tenant_id,
            memory=memory,
            cpu=cpu,
            created_at=now,
            expires_at=now + ttl_seconds,
            status="pending"
        )
        serialized = json.dumps(self._to_dict(res))
        success = await self._client.set(key, serialized, ex=ttl_seconds, nx=True)
        if success:
            await self._client.sadd(f"node_reservations:{node_id}", execution_id)
            return True
        return False

    async def claim_reservation(self, execution_id: str) -> bool:
        key = f"reservation:{execution_id}"
        val = await self._client.get(key)
        if not val:
            return False
        d = json.loads(val)
        res = self._from_dict(d)
        if res.status != "pending" or time.time() >= res.expires_at:
            return False
        res.status = "claimed"
        # Preserve remaining TTL
        remaining = int(max(1, res.expires_at - time.time()))
        await self._client.set(key, json.dumps(self._to_dict(res)), ex=remaining)
        return True

    async def release_reservation(self, execution_id: str, reason: str = "Released by scheduler") -> bool:
        key = f"reservation:{execution_id}"
        val = await self._client.get(key)
        if not val:
            return False
        d = json.loads(val)
        res = self._from_dict(d)
        if res.status == "pending":
            res.status = "released"
            await self._client.delete(key)
            await self._client.srem(f"node_reservations:{res.node_id}", execution_id)
            await self._emit_audit_event(
                "ReservationReleased",
                {
                    "execution_id": execution_id,
                    "reservation_id": res.reservation_id,
                    "node_id": res.node_id,
                    "tenant_id": res.tenant_id,
                    "scheduler_id": res.scheduler_id,
                    "reason": reason
                }
            )
            return True
        return False

    async def get_node_pending_reservations(self, node_id: str) -> List[ExecutionReservation]:
        skey = f"node_reservations:{node_id}"
        exec_ids = await self._client.smembers(skey)
        pending = []
        now = time.time()
        for exec_id in list(exec_ids):
            key = f"reservation:{exec_id}"
            val = await self._client.get(key)
            if not val:
                # Key expired, clean up set
                await self._client.srem(skey, exec_id)
                continue
            d = json.loads(val)
            res = self._from_dict(d)
            if res.status == "pending" and now < res.expires_at:
                pending.append(res)
            elif now >= res.expires_at:
                await self._client.srem(skey, exec_id)
        return pending

    async def get_reservation(self, execution_id: str) -> Optional[ExecutionReservation]:
        key = f"reservation:{execution_id}"
        val = await self._client.get(key)
        if not val:
            return None
        return self._from_dict(json.loads(val))

    async def cleanup_expired_reservations(self) -> List[str]:
        # Expired reservations are naturally evicted by Redis EXPIRE TTL,
        # but to emit audits, we must monitor expired keys.
        # For the mock/test environment, we clean up manually:
        keys = await self._client.keys("reservation:*")
        expired = []
        now = time.time()
        for key in keys:
            val = await self._client.get(key)
            if val:
                d = json.loads(val)
                res = self._from_dict(d)
                if res.status == "pending" and now >= res.expires_at:
                    await self._client.delete(key)
                    await self._client.srem(f"node_reservations:{res.node_id}", res.execution_id)
                    expired.append(res.execution_id)
                    await self._emit_audit_event(
                        "ReservationExpired",
                        {
                            "execution_id": res.execution_id,
                            "reservation_id": res.reservation_id,
                            "node_id": res.node_id,
                            "tenant_id": res.tenant_id,
                            "scheduler_id": res.scheduler_id,
                            "reason": "TTL expired"
                        }
                    )
        return expired

class VersionCompatibilityPolicy(ABC):
    @abstractmethod
    async def allows(self, scheduler_version: str, node_version: str) -> bool:
        pass

class DefaultVersionCompatibilityPolicy(VersionCompatibilityPolicy):
    async def allows(self, scheduler_version: str, node_version: str) -> bool:
        try:
            s_parts = [int(p) for p in scheduler_version.split(".")]
            n_parts = [int(p) for p in node_version.split(".")]
        except ValueError:
            return False

        if len(s_parts) < 2 or len(n_parts) < 2:
            return False

        if s_parts[0] != n_parts[0]:
            return False

        if abs(s_parts[1] - n_parts[1]) > 1:
            return False

        return True

class CapacityPolicy(ABC):
    @abstractmethod
    async def can_allocate(self, node: "RuntimeNode", memory: int, cpu: float) -> bool:
        pass

class StrictOneToOneCapacityPolicy(CapacityPolicy):
    def __init__(self, reservation_store: ReservationStore):
        self.reservation_store = reservation_store

    async def can_allocate(self, node: "RuntimeNode", memory: int, cpu: float) -> bool:
        pending = await self.reservation_store.get_node_pending_reservations(node.node_id)
        pending_mem = sum(r.memory for r in pending)
        pending_cpu = sum(r.cpu for r in pending)

        remaining_memory = node.total_memory - (node.allocated_memory + pending_mem)
        remaining_cpu = node.total_cpu - (node.allocated_cpu + pending_cpu)
        return memory <= remaining_memory and cpu <= remaining_cpu

@dataclass
class RuntimeNode:
    node_id: str
    tenant_scope: str = "default"
    runtime_types: List[str] = field(default_factory=lambda: ["docker"])
    total_memory: int = 512       # MB
    allocated_memory: int = 0
    total_cpu: float = 0.5        # cores
    allocated_cpu: float = 0.0
    health_status: str = "healthy"  # "healthy" | "degraded" | "draining" | "offline" | "quarantined"
    last_heartbeat: float = field(default_factory=time.time)
    software_version: str = "1.0.0"
    verification_failures: int = 0
    region: str = "us-east-1"
    availability_zone: Optional[str] = None

class FleetRegistry:
    """Manages active runtime node registrations, compatibility policy, capacity limits, and execution assignments."""

    def __init__(
        self,
        stale_timeout_sec: float = 30.0,
        compatibility_policy: Optional[VersionCompatibilityPolicy] = None,
        capacity_policy: Optional[CapacityPolicy] = None,
        reservation_store: Optional[ReservationStore] = None
    ):
        self.stale_timeout_sec = stale_timeout_sec
        self.compatibility_policy = compatibility_policy or DefaultVersionCompatibilityPolicy()
        self.reservation_store = reservation_store or InMemoryReservationStore()
        self.capacity_policy = capacity_policy or StrictOneToOneCapacityPolicy(self.reservation_store)
        self._nodes: Dict[str, RuntimeNode] = {}
        
        self._resource_lock = asyncio.Lock()
        self._draining_nodes: Dict[str, float] = {}

        self._ownerships: Dict[str, str] = {}  # execution_id -> assigned_node_id
        self._execution_status: Dict[str, str] = {}  # execution_id -> status ("assigned", "acknowledged", "completed")
        self._execution_has_side_effects: Dict[str, bool] = {}  # execution_id -> bool
        self._execution_resources: Dict[str, tuple] = {}  # execution_id -> (memory, cpu)

    def register_node(self, node: RuntimeNode) -> None:
        node.last_heartbeat = time.time()
        if node.node_id in self._nodes:
            old_node = self._nodes[node.node_id]
            node.allocated_memory = old_node.allocated_memory
            node.allocated_cpu = old_node.allocated_cpu
            node.verification_failures = old_node.verification_failures
            if old_node.health_status in ("draining", "quarantined"):
                node.health_status = old_node.health_status
        self._nodes[node.node_id] = node
        logger.info(f"Node {node.node_id} successfully registered (tenant: {node.tenant_scope})")

    def drain_node(self, node_id: str) -> None:
        if node_id in self._nodes:
            self._nodes[node_id].health_status = "draining"
            self._draining_nodes[node_id] = time.time()
            logger.info(f"Node {node_id} transitioned to draining state")

    def quarantine_node(self, node_id: str) -> None:
        if node_id in self._nodes:
            self._nodes[node_id].health_status = "quarantined"
            logger.warning(f"Node {node_id} transitioned to quarantined state")

    def record_verification_failure(self, node_id: str) -> None:
        if node_id in self._nodes:
            node = self._nodes[node_id]
            node.verification_failures += 1
            logger.warning(f"Node {node_id} verification failure count: {node.verification_failures}")
            if node.verification_failures >= 3:
                self.quarantine_node(node_id)

    async def get_healthy_nodes(
        self,
        tenant_id: str,
        scheduler_version: str = "1.0.0"
    ) -> List[RuntimeNode]:
        current_time = time.time()
        healthy = []
        
        for node in self._nodes.values():
            elapsed = current_time - node.last_heartbeat
            
            if elapsed > 30.0:
                if node.health_status != "offline":
                    logger.warning(f"Node {node.node_id} heartbeats stopped. Transitioning to offline.")
                    node.health_status = "offline"
            elif elapsed > 15.0:
                if node.health_status not in ("degraded", "offline", "quarantined", "draining"):
                    logger.warning(f"Node {node.node_id} heartbeat delayed. Transitioning to degraded.")
                    node.health_status = "degraded"
            elif node.health_status == "degraded" and elapsed <= 15.0:
                node.health_status = "healthy"

            if node.health_status in ("offline", "draining", "quarantined"):
                continue
                
            if node.tenant_scope != tenant_id:
                continue
                
            compatible = await self.compatibility_policy.allows(scheduler_version, node.software_version)
            if not compatible:
                continue
                
            healthy.append(node)
            
        return healthy

    async def select_node(
        self,
        required_runtime: str,
        tenant_id: str,
        scheduler_version: str = "1.0.0",
        required_memory: int = 0,
        required_cpu: float = 0.0,
        required_region: Optional[str] = None,
        required_zone: Optional[str] = None
    ) -> Optional[RuntimeNode]:
        candidates = await self.get_healthy_nodes(tenant_id, scheduler_version)
        
        # Enforce region constraint matching
        if required_region:
            candidates = [n for n in candidates if n.region == required_region]
        if required_zone:
            candidates = [n for n in candidates if n.availability_zone == required_zone]
            
        matched = [node for node in candidates if required_runtime in node.runtime_types]
        if not matched:
            logger.warning(f"No healthy compatible nodes found for runtime '{required_runtime}'")
            return None

        eligible = []
        for node in matched:
            if await self.capacity_policy.can_allocate(node, required_memory, required_cpu):
                eligible.append(node)
                
        if not eligible:
            logger.warning("No nodes have sufficient unallocated capacity")
            return None

        eligible.sort(key=lambda n: (n.total_memory - n.allocated_memory), reverse=True)
        return eligible[0]

    # Dynamic capacity allocate and release
    async def allocate_resources(self, node_id: str, memory: int, cpu: float) -> bool:
        async with self._resource_lock:
            if node_id not in self._nodes:
                return False
            node = self._nodes[node_id]
            can_allocate = await self.capacity_policy.can_allocate(node, memory, cpu)
            if not can_allocate:
                return False
            node.allocated_memory += memory
            node.allocated_cpu += cpu
            return True

    async def release_resources(self, node_id: str, memory: int, cpu: float) -> None:
        async with self._resource_lock:
            if node_id not in self._nodes:
                return
            node = self._nodes[node_id]
            node.allocated_memory = max(0, node.allocated_memory - memory)
            node.allocated_cpu = max(0.0, node.allocated_cpu - cpu)

    async def check_draining_timeouts(self, grace_period_sec: float = 300.0) -> List[str]:
        current_time = time.time()
        transitioned = []
        for node_id, start_time in list(self._draining_nodes.items()):
            if current_time - start_time >= grace_period_sec:
                if node_id in self._nodes:
                    node = self._nodes[node_id]
                    if node.health_status == "draining":
                        node.health_status = "offline"
                        transitioned.append(node_id)
                        logger.warning(f"[AUDIT] Draining timeout expired for node {node_id}. Transitioned to offline.")
                del self._draining_nodes[node_id]
        return transitioned

    # Durable Execution Ownership Assignment Methods
    async def assign_execution(
        self,
        execution_id: str,
        node_id: str,
        memory: int = 0,
        cpu: float = 0.0,
        has_side_effects: bool = False
    ) -> None:
        """Atomically persists ownership mapping of execution_id to node_id before work becomes active."""
        if execution_id in self._ownerships:
            raise ValueError(f"Execution {execution_id} is already assigned to node {self._ownerships[execution_id]}")
        
        async with self._resource_lock:
            if node_id in self._nodes:
                node = self._nodes[node_id]
                node.allocated_memory += memory
                node.allocated_cpu += cpu
            self._ownerships[execution_id] = node_id
            self._execution_status[execution_id] = "assigned"
            self._execution_has_side_effects[execution_id] = has_side_effects
            self._execution_resources[execution_id] = (memory, cpu)
            logger.info(f"Execution {execution_id} durably assigned to node {node_id}")

    async def reassign_execution(self, execution_id: str, node_id: str) -> None:
        """Reassigns an execution to a different node if not yet acknowledged or completed, and if it has no side effects."""
        if execution_id not in self._ownerships:
            raise ValueError(f"Execution {execution_id} is not assigned")
        if self._execution_status[execution_id] == "acknowledged":
            raise ValueError(f"Execution {execution_id} is already acknowledged")
        if self._execution_status[execution_id] == "completed":
            raise ValueError(f"Execution {execution_id} is already completed")
        if self._execution_has_side_effects.get(execution_id, False):
            raise ValueError(f"Execution {execution_id} has side effects and cannot be reassigned")
        
        async with self._resource_lock:
            old_node_id = self._ownerships[execution_id]
            mem, cpu = self._execution_resources.get(execution_id, (0, 0.0))
            
            # Release resources on the old node
            if old_node_id in self._nodes:
                old_node = self._nodes[old_node_id]
                old_node.allocated_memory = max(0, old_node.allocated_memory - mem)
                old_node.allocated_cpu = max(0.0, old_node.allocated_cpu - cpu)
                
            # Allocate resources on the new node
            if node_id in self._nodes:
                node = self._nodes[node_id]
                node.allocated_memory += mem
                node.allocated_cpu += cpu
                
            self._ownerships[execution_id] = node_id
            logger.info(f"Execution {execution_id} reassigned from node {old_node_id} to {node_id}")

    async def claim_reservation(self, execution_id: str) -> bool:
        """Claim reservation atomically when node acknowledges receiving the contract."""
        async with self._resource_lock:
            success = await self.reservation_store.claim_reservation(execution_id)
            if not success:
                return False
            
            res = await self.reservation_store.get_reservation(execution_id)
            if res and res.node_id in self._nodes:
                node = self._nodes[res.node_id]
                node.allocated_memory += res.memory
                node.allocated_cpu += res.cpu
                self._ownerships[execution_id] = res.node_id
                self._execution_status[execution_id] = "claimed"
                self._execution_resources[execution_id] = (res.memory, res.cpu)
                return True
            return False

    async def acknowledge_execution(self, execution_id: str) -> None:
        """Node acknowledges execution contract."""
        if execution_id not in self._ownerships:
            raise ValueError(f"Execution {execution_id} has no assigned owner to acknowledge")
        self._execution_status[execution_id] = "acknowledged"

    async def complete_execution(self, execution_id: str) -> None:
        """Marks execution as completed and releases resources."""
        async with self._resource_lock:
            res = await self.reservation_store.get_reservation(execution_id)
            node_id = self._ownerships.get(execution_id)
            
            self._execution_status[execution_id] = "completed"
            
            if node_id in self._nodes:
                node = self._nodes[node_id]
                if res and res.status == "claimed":
                    node.allocated_memory = max(0, node.allocated_memory - res.memory)
                    node.allocated_cpu = max(0.0, node.allocated_cpu - res.cpu)
                elif execution_id in self._execution_resources:
                    mem, cpu = self._execution_resources[execution_id]
                    node.allocated_memory = max(0, node.allocated_memory - mem)
                    node.allocated_cpu = max(0.0, node.allocated_cpu - cpu)
            
            await self.reservation_store.release_reservation(execution_id, "Execution completed")
            if execution_id in self._execution_resources:
                del self._execution_resources[execution_id]
            logger.info(f"Execution {execution_id} completed, resources released.")
