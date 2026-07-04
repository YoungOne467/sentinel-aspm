import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
from dataclasses import dataclass

from packages.execution.isolation import IsolationLevel

logger = logging.getLogger(__name__)

@dataclass
class TenantQuota:
    tenant_id: str
    max_memory: int                # MB
    max_cpu: float                 # cores
    max_firecracker_slots: int
    max_external_network_slots: int
    max_queued_workloads: int = 100
    tenant_tier: str = "standard"

class TenantQuotaStore(ABC):
    @abstractmethod
    async def get_quota(self, tenant_id: str) -> TenantQuota:
        """
        Retrieves the TenantQuota configuration for a tenant.
        """
        pass

class InMemoryTenantQuotaStore(TenantQuotaStore):
    def __init__(self):
        self._quotas: Dict[str, TenantQuota] = {}

    def set_quota(self, quota: TenantQuota) -> None:
        self._quotas[quota.tenant_id] = quota

    async def get_quota(self, tenant_id: str) -> TenantQuota:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        if tenant_id not in self._quotas:
            # Return a default generous quota
            return TenantQuota(
                tenant_id=tenant_id,
                max_memory=4096,
                max_cpu=4.0,
                max_firecracker_slots=5,
                max_external_network_slots=5,
                max_queued_workloads=100
            )
        return self._quotas[tenant_id]

class DatabaseTenantQuotaStore(TenantQuotaStore):
    """
    Authoritative tenant quota store that queries the Control Plane database.
    Provides fallback/mock support if the database is unavailable or the table doesn't exist.
    """
    def __init__(self, session_factory=None):
        self.session_factory = session_factory
        
    async def get_quota(self, tenant_id: str) -> TenantQuota:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
            
        if self.session_factory is not None:
            try:
                async with self.session_factory() as session:
                    from sqlalchemy import text
                    stmt = text("SELECT max_memory, max_cpu, max_firecracker_slots, max_external_network_slots, max_queued_workloads FROM tenant_quotas WHERE tenant_id = :tenant_id")
                    res = await session.execute(stmt, {"tenant_id": tenant_id})
                    row = res.fetchone()
                    if row:
                        return TenantQuota(
                            tenant_id=tenant_id,
                            max_memory=row[0],
                            max_cpu=row[1],
                            max_firecracker_slots=row[2],
                            max_external_network_slots=row[3],
                            max_queued_workloads=row[4]
                        )
            except Exception as e:
                logger.warning(f"Database error fetching quota for tenant {tenant_id}: {e}. Using default.")
                
        # Default fallback
        return TenantQuota(
            tenant_id=tenant_id,
            max_memory=4096,
            max_cpu=4.0,
            max_firecracker_slots=5,
            max_external_network_slots=5,
            max_queued_workloads=100
        )

class CachedTenantQuotaStore(TenantQuotaStore):
    """
    Cached runtime quota wrapper to avoid excessive database hits during burst scheduling.
    Supports TTL expiration and explicit invalidation.
    """

    def __init__(self, backing_store: TenantQuotaStore, cache_ttl_sec: float = 60.0, quota_cache_ttl_seconds: Optional[float] = None):
        self._backing_store = backing_store
        self.cache_ttl_sec = quota_cache_ttl_seconds if quota_cache_ttl_seconds is not None else cache_ttl_sec
        # Maps tenant_id -> (TenantQuota, cache_timestamp)
        self._cache: Dict[str, tuple] = {}
        self.db_hits = 0

    async def get_quota(self, tenant_id: str) -> TenantQuota:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        now = time.time()
        if tenant_id in self._cache:
            quota, timestamp = self._cache[tenant_id]
            if now - timestamp < self.cache_ttl_sec:
                return quota
                
        # Cache miss or expired
        self.db_hits += 1
        quota = await self._backing_store.get_quota(tenant_id)
        self._cache[tenant_id] = (quota, now)
        return quota

    def invalidate(self, tenant_id: str) -> None:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        if tenant_id in self._cache:
            del self._cache[tenant_id]

    def invalidate_all(self) -> None:
        self._cache.clear()

class TenantQuotaPolicy(ABC):
    @abstractmethod
    async def allows(
        self,
        tenant_id: str,
        quota_store: TenantQuotaStore,
        registry: Any,
        memory: int,
        cpu: float,
        isolation_level: IsolationLevel,
        queued_count: int
    ) -> bool:
        pass

class DefaultTenantQuotaPolicy(TenantQuotaPolicy):
    async def allows(
        self,
        tenant_id: str,
        quota_store: TenantQuotaStore,
        registry: Any,
        memory: int,
        cpu: float,
        isolation_level: IsolationLevel,
        queued_count: int
    ) -> bool:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        quota = await quota_store.get_quota(tenant_id)
        
        # Sum memory, CPU, and isolation slot usage currently consumed by this tenant
        current_mem = 0
        current_cpu = 0
        current_fc_slots = 0
        current_ext_slots = 0
        now = time.time()

        # 1. Sum from active ownerships in registry
        for exec_id, node_id in registry._ownerships.items():
            status = registry._execution_status.get(exec_id)
            if status in ("assigned", "acknowledged", "claimed"):
                res = await registry.reservation_store.get_reservation(exec_id)
                if res and res.tenant_id == tenant_id:
                    current_mem += res.memory
                    current_cpu += res.cpu
                    # Check if node supports Firecracker
                    if res.node_id in registry._nodes:
                        node = registry._nodes[res.node_id]
                        if "firecracker" in node.runtime_types:
                            current_fc_slots += 1
                        # If capability network:external was checked
                        # Note: res may have capabilities stored, let's check or fallback
                        capabilities = getattr(res, "capabilities", [])
                        if "network:external" in capabilities:
                            current_ext_slots += 1

        # 2. Sum from pending reservations in the store (excluding claimed/released/expired)
        if hasattr(registry.reservation_store, "_reservations"):
            for res in registry.reservation_store._reservations.values():
                if res.tenant_id == tenant_id and res.status == "pending" and now < res.expires_at:
                    current_mem += res.memory
                    current_cpu += res.cpu
                    if res.node_id in registry._nodes:
                        node = registry._nodes[res.node_id]
                        if "firecracker" in node.runtime_types:
                            current_fc_slots += 1
                        capabilities = getattr(res, "capabilities", [])
                        if "network:external" in capabilities:
                            current_ext_slots += 1
        elif hasattr(registry.reservation_store, "get_node_pending_reservations"):
            for node_id in registry._nodes.keys():
                pending = await registry.reservation_store.get_node_pending_reservations(node_id)
                for res in pending:
                    if res.tenant_id == tenant_id:
                        current_mem += res.memory
                        current_cpu += res.cpu
                        node = registry._nodes[node_id]
                        if "firecracker" in node.runtime_types:
                            current_fc_slots += 1
                        capabilities = getattr(res, "capabilities", [])
                        if "network:external" in capabilities:
                            current_ext_slots += 1

        # 3. Check memory limit
        if current_mem + memory > quota.max_memory:
            logger.warning(f"Tenant {tenant_id} memory quota exceeded. Usage: {current_mem}MB, Limit: {quota.max_memory}MB")
            return False

        # 4. Check CPU limit
        if current_cpu + cpu > quota.max_cpu:
            logger.warning(f"Tenant {tenant_id} CPU quota exceeded. Usage: {current_cpu}, Limit: {quota.max_cpu}")
            return False

        # 5. Check isolation slots limits
        if isolation_level == IsolationLevel.FIRECRACKER:
            if current_fc_slots + 1 > quota.max_firecracker_slots:
                logger.warning(f"Tenant {tenant_id} Firecracker slots quota exceeded.")
                return False
            if current_ext_slots + 1 > quota.max_external_network_slots:
                logger.warning(f"Tenant {tenant_id} external network slots quota exceeded.")
                return False

        # 6. Check queued count limit
        if queued_count >= quota.max_queued_workloads:
            logger.warning(f"Tenant {tenant_id} max queued workloads limit reached.")
            return False

        return True
