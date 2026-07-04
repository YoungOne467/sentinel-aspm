import time
import logging
from typing import Dict, Any, Optional, Set
from packages.execution.interfaces import ExecutionContract
from packages.execution.fleet import FleetRegistry, ExecutionReservation
from packages.execution.isolation import IsolationLevel, IsolationMatchPolicy, DefaultIsolationMatchPolicy
from packages.execution.quotas import TenantQuotaStore, TenantQuotaPolicy, DefaultTenantQuotaPolicy
from packages.execution.queues import WorkloadQueueManager
from packages.execution.firecracker import ProductionFirecrackerPolicy
from packages.execution.ha import DatabaseHealthProvider, SimpleDatabaseHealthProvider, ActiveActiveCoordinator
from packages.audit.interfaces import AuditEvent
from packages.audit.emitter import audit_emitter
from packages.observability.metrics import (
    scheduler_selection_duration,
    scheduler_failed_matches,
    scheduler_capacity_exhaustions,
    lease_acquisition_success,
    lease_renewal_failure,
    regional_routing_rejection_count
)

logger = logging.getLogger(__name__)

class SchedulerEvent(AuditEvent):
    pass

class FleetScheduler:
    """
    Orchestrates SENTINEL workload scheduling flow across a distributed node fleet.
    Enforces database health state constraints, tenant quotas, isolation rules,
    strict capacity limits, and active-active scheduler coordination.
    """
    def __init__(
        self,
        registry: FleetRegistry,
        quota_store: TenantQuotaStore,
        quota_policy: Optional[TenantQuotaPolicy] = None,
        isolation_policy: Optional[IsolationMatchPolicy] = None,
        queue_manager: Optional[WorkloadQueueManager] = None,
        db_health_provider: Optional[DatabaseHealthProvider] = None,
        production_firecracker_policy: Optional[ProductionFirecrackerPolicy] = None,
        coordinator: Optional[ActiveActiveCoordinator] = None,
        lease_manager: Optional[Any] = None,
        scheduler_id: str = "scheduler-default",
        lease_name: str = "scheduler-leader",
        budget_manager: Optional[Any] = None,
        session_factory: Optional[Any] = None,
        token_rate: float = 0.00002
    ):
        self.registry = registry
        self.quota_store = quota_store
        self.quota_policy = quota_policy or DefaultTenantQuotaPolicy()
        self.isolation_policy = isolation_policy or DefaultIsolationMatchPolicy()
        self.queue_manager = queue_manager or WorkloadQueueManager()
        self.db_health_provider = db_health_provider or SimpleDatabaseHealthProvider("healthy")
        self.production_firecracker_policy = production_firecracker_policy or ProductionFirecrackerPolicy()
        self.coordinator = coordinator or ActiveActiveCoordinator(registry.reservation_store)
        self.lease_manager = lease_manager
        self.scheduler_id = scheduler_id
        self.lease_name = lease_name
        self.budget_manager = budget_manager
        self.session_factory = session_factory
        self.token_rate = token_rate
        self._contracts: Dict[str, ExecutionContract] = {}

    async def _emit_audit_event(self, name: str, payload: Dict[str, Any]):
        try:
            await audit_emitter.emit(
                SchedulerEvent(name=name, payload=payload),
                actor="system"
            )
        except Exception as e:
            logger.error(f"Failed to emit scheduler audit event {name}: {e}")

    async def dispatch_contract(self, node_id: str, contract: ExecutionContract) -> bool:
        """
        Dispatches contract to target node. Can be overridden or mocked in tests.
        """
        return True

    async def schedule(self, contract: ExecutionContract) -> bool:
        """
        Orchestrates strict scheduling sequence:
        1. Check DB Health
        2. Check isolation requirements
        3. Check Firecracker eligibility policy (gate check)
        4. Check tenant quota
        5. Check node capacity
        6. Acquire coordination lock (active-active scheduler coordination)
        7. Create reservation atomically
        8. Dispatch contract
        9. Node acknowledges contract
        10. Claim reservation
        """
        if self.lease_manager:
            is_leader = await self.lease_manager.is_lease_active(self.lease_name, self.scheduler_id)
            if not is_leader:
                logger.error(f"Scheduler {self.scheduler_id} does not hold active leader lease: failing closed")
                lease_renewal_failure.add(1)
                raise RuntimeError("Not the active lease holder")

        if not contract.tenant_id or contract.tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")

        # Budget Check
        if self.budget_manager and self.session_factory:
            projected_tokens = int(contract.env.get("PROJECTED_TOKENS", 10000))
            projected_infra = float(contract.env.get("PROJECTED_INFRA_COST", 0.05))
            async with self.session_factory() as session:
                try:
                    await self.budget_manager.check_budget_pre_dispatch(
                        tenant_id=contract.tenant_id,
                        workspace_id=contract.workspace_id or "default",
                        projected_tokens=projected_tokens,
                        projected_infra_cost=projected_infra,
                        token_rate=self.token_rate,
                        session=session
                    )
                    await session.commit()
                except Exception as e:
                    await session.rollback()
                    logger.error(f"Pre-dispatch budget validation failed: {e}")
                    raise

        # 1. Check DB Health
        db_state = await self.db_health_provider.get_health_state()
        if db_state == "unavailable":
            logger.error("Database unavailable: failing closed for scheduling")
            raise RuntimeError("Database unavailable: failing closed for scheduling")
        elif db_state == "degraded":
            logger.warning("Database state degraded. Proceeding with caution.")

        # Determine resource requirements
        memory = int(contract.env.get("REQUIRED_MEMORY", contract.env.get("memory", 128)))
        cpu = float(contract.env.get("REQUIRED_CPU", contract.env.get("cpu", 0.1)))
        priority = contract.env.get("PRIORITY", contract.env.get("priority", "low"))

        # 2. Check isolation
        isolation_level = await self.isolation_policy.required_isolation(set(contract.capabilities))
        
        # 3. Verify Production Firecracker Gate
        if isolation_level == IsolationLevel.FIRECRACKER:
            if not self.production_firecracker_policy.is_eligible():
                logger.error("Firecracker required but ProductionFirecrackerPolicy gates have not passed.")
                raise ValueError("Firecracker microVM scheduling is not eligible: production readiness gates not met.")

        await self._emit_audit_event("IsolationLevelSelected", {
            "execution_id": contract.execution_id,
            "tenant_id": contract.tenant_id,
            "isolation_level": isolation_level.value,
            "capabilities": list(contract.capabilities)
        })

        quota = await self.quota_store.get_quota(contract.tenant_id)
        tenant_tier = getattr(quota, "tenant_tier", "standard")
        runtime_type = isolation_level.value

        # 4. Check tenant quota
        queued_count = self.queue_manager.get_queue_depth(contract.tenant_id)
        quota_allowed = await self.quota_policy.allows(
            tenant_id=contract.tenant_id,
            quota_store=self.quota_store,
            registry=self.registry,
            memory=memory,
            cpu=cpu,
            isolation_level=isolation_level,
            queued_count=queued_count
        )

        start_time = time.perf_counter()

        # 5. Check capacity (select node)
        node = None
        if quota_allowed:
            node = await self.registry.select_node(
                required_runtime=runtime_type,
                tenant_id=contract.tenant_id,
                scheduler_version=contract.scheduler_version,
                required_memory=memory,
                required_cpu=cpu,
                required_region=contract.required_region,
                required_zone=contract.required_zone
            )

        duration = time.perf_counter() - start_time
        scheduler_selection_duration.record(duration, {
            "tenant_tier": tenant_tier,
            "runtime_type": runtime_type
        })

        if not quota_allowed or not node:
            if not quota_allowed:
                logger.info(f"Quota exhausted for tenant {contract.tenant_id}. Queueing workload.")
            else:
                logger.info(f"Capacity exhausted for tenant {contract.tenant_id}. Queueing workload.")
                if contract.required_region:
                    all_healthy = await self.registry.get_healthy_nodes(contract.tenant_id, contract.scheduler_version)
                    runtime_healthy = [n for n in all_healthy if runtime_type in n.runtime_types]
                    if runtime_healthy:
                        logger.warning(f"Regional routing mismatch: workload region {contract.required_region} had no compatible nodes.")
                        regional_routing_rejection_count.add(1)
                
                scheduler_capacity_exhaustions.add(1, {
                    "tenant_tier": tenant_tier,
                    "runtime_type": runtime_type
                })

            # Queue workload
            success = self.queue_manager.enqueue(
                tenant_id=contract.tenant_id,
                item=contract,
                tenant_tier=tenant_tier,
                runtime_type=runtime_type,
                priority=priority
            )
            if not success:
                raise ValueError(f"Backpressure rejection: Queue depth limit reached for tenant {contract.tenant_id}")
            return False

        # 6. Acquire coordination lock (active-active coordination)
        lock_acquired = await self.coordinator.acquire_coordination_lock(contract.execution_id)
        if not lock_acquired:
            logger.warning(f"Failed to acquire coordination lock for execution {contract.execution_id}")
            scheduler_failed_matches.add(1, {
                "tenant_tier": tenant_tier,
                "runtime_type": runtime_type
            })
            success = self.queue_manager.enqueue(
                tenant_id=contract.tenant_id,
                item=contract,
                tenant_tier=tenant_tier,
                runtime_type=runtime_type,
                priority=priority
            )
            if not success:
                raise ValueError(f"Backpressure rejection: Queue depth limit reached for tenant {contract.tenant_id}")
            return False

        # 7. Create reservation atomically (authoritative safety)
        reservation_id = f"res-{contract.execution_id}"
        # Use default TTL of 10 seconds for automated failover recovery
        res_success = await self.registry.reservation_store.create_reservation(
            reservation_id=reservation_id,
            execution_id=contract.execution_id,
            node_id=node.node_id,
            scheduler_id=contract.scheduler_id,
            tenant_id=contract.tenant_id,
            memory=memory,
            cpu=cpu,
            ttl_seconds=10
        )
        if not res_success:
            logger.warning(f"Reservation collision or double allocation check failed for execution {contract.execution_id}")
            await self.coordinator.release_coordination_lock(contract.execution_id)
            scheduler_failed_matches.add(1, {
                "tenant_tier": tenant_tier,
                "runtime_type": runtime_type
            })
            success = self.queue_manager.enqueue(
                tenant_id=contract.tenant_id,
                item=contract,
                tenant_tier=tenant_tier,
                runtime_type=runtime_type,
                priority=priority
            )
            if not success:
                raise ValueError(f"Backpressure rejection: Queue depth limit reached for tenant {contract.tenant_id}")
            return False

        # 8. Dispatch contract
        self._contracts[contract.execution_id] = contract
        dispatch_ok = await self.dispatch_contract(node.node_id, contract)
        if not dispatch_ok:
            logger.error(f"Dispatch failed to node {node.node_id} for execution {contract.execution_id}")
            await self.registry.reservation_store.release_reservation(contract.execution_id, "Dispatch failed")
            await self.coordinator.release_coordination_lock(contract.execution_id)
            scheduler_failed_matches.add(1, {
                "tenant_tier": tenant_tier,
                "runtime_type": runtime_type
            })
            return False

        return True

    async def acknowledge_node_receipt(self, execution_id: str) -> bool:
        """
        9. Node acknowledges receipt of contract.
        10. Claim reservation (transitions pending reservation to claimed, registers capacity usage).
        """
        # Node acknowledges execution and scheduler claims reservation
        res = await self.registry.reservation_store.get_reservation(execution_id)
        if not res:
            logger.warning(f"No reservation found for execution {execution_id} to acknowledge")
            return False

        # Atomic claim transitions reservation state to claimed, updates node allocation and ownerships
        success = await self.registry.claim_reservation(execution_id)
        if not success:
            logger.warning(f"Failed to claim reservation for execution {execution_id} (expired or already claimed)")
            return False

        await self.registry.acknowledge_execution(execution_id)
        # Release coordination lock on success since reservation is now claimed and ownership established
        await self.coordinator.release_coordination_lock(execution_id)
        return True

    async def process_queue(self) -> int:
        """
        Attempts to schedule queued workloads in a round-robin fashion.
        Returns the number of successfully scheduled and dispatched workloads.
        """
        scheduled_count = 0
        total_queued = self.queue_manager.get_total_depth()

        for _ in range(total_queued):
            if self.lease_manager:
                is_leader = await self.lease_manager.is_lease_active(self.lease_name, self.scheduler_id)
                if not is_leader:
                    logger.error(f"Scheduler {self.scheduler_id} lost active leader lease during queue processing: stopping.")
                    break

            # Check DB health first
            db_state = await self.db_health_provider.get_health_state()
            if db_state == "unavailable":
                break

            contract = self.queue_manager.dequeue()
            if not contract:
                break

            # Budget Check
            if self.budget_manager and self.session_factory:
                projected_tokens = int(contract.env.get("PROJECTED_TOKENS", 10000))
                projected_infra = float(contract.env.get("PROJECTED_INFRA_COST", 0.05))
                async with self.session_factory() as session:
                    try:
                        await self.budget_manager.check_budget_pre_dispatch(
                            tenant_id=contract.tenant_id,
                            workspace_id=contract.workspace_id or "default",
                            projected_tokens=projected_tokens,
                            projected_infra_cost=projected_infra,
                            token_rate=self.token_rate,
                            session=session
                        )
                        await session.commit()
                    except Exception as e:
                        await session.rollback()
                        logger.error(f"Queue processing: budget limit check failed for contract {contract.execution_id}: {e}")
                        # Skip this task, do not re-enqueue it since budget is breached
                        continue

            memory = int(contract.env.get("REQUIRED_MEMORY", contract.env.get("memory", 128)))
            cpu = float(contract.env.get("REQUIRED_CPU", contract.env.get("cpu", 0.1)))
            priority = contract.env.get("PRIORITY", contract.env.get("priority", "low"))
            isolation_level = await self.isolation_policy.required_isolation(set(contract.capabilities))
            
            # Verify Production Firecracker Gate
            if isolation_level == IsolationLevel.FIRECRACKER and not self.production_firecracker_policy.is_eligible():
                logger.error("Queued Firecracker workload skipped: gates not met.")
                # We skip and drop or reject immediately because the readiness policy blocks it
                continue

            quota = await self.quota_store.get_quota(contract.tenant_id)
            tenant_tier = getattr(quota, "tenant_tier", "standard")
            runtime_type = isolation_level.value

            quota_allowed = await self.quota_policy.allows(
                tenant_id=contract.tenant_id,
                quota_store=self.quota_store,
                registry=self.registry,
                memory=memory,
                cpu=cpu,
                isolation_level=isolation_level,
                queued_count=self.queue_manager.get_queue_depth(contract.tenant_id)
            )

            node = None
            if quota_allowed:
                node = await self.registry.select_node(
                    required_runtime=runtime_type,
                    tenant_id=contract.tenant_id,
                    scheduler_version=contract.scheduler_version,
                    required_memory=memory,
                    required_cpu=cpu,
                    required_region=contract.required_region,
                    required_zone=contract.required_zone
                )

            if quota_allowed and not node and contract.required_region:
                all_healthy = await self.registry.get_healthy_nodes(contract.tenant_id, contract.scheduler_version)
                runtime_healthy = [n for n in all_healthy if runtime_type in n.runtime_types]
                if runtime_healthy:
                    logger.warning(f"Regional routing mismatch in queue processing: workload region {contract.required_region} had no compatible nodes.")
                    regional_routing_rejection_count.add(1)

            if quota_allowed and node:
                # Active-active coordination lock
                lock_acquired = await self.coordinator.acquire_coordination_lock(contract.execution_id)
                if lock_acquired:
                    reservation_id = f"res-{contract.execution_id}"
                    res_success = await self.registry.reservation_store.create_reservation(
                        reservation_id=reservation_id,
                        execution_id=contract.execution_id,
                        node_id=node.node_id,
                        scheduler_id=contract.scheduler_id,
                        tenant_id=contract.tenant_id,
                        memory=memory,
                        cpu=cpu,
                        ttl_seconds=10
                    )
                    if res_success:
                        self._contracts[contract.execution_id] = contract
                        dispatch_ok = await self.dispatch_contract(node.node_id, contract)
                        if dispatch_ok:
                            scheduled_count += 1
                            continue
                        else:
                            await self.registry.reservation_store.release_reservation(contract.execution_id, "Dispatch failed")
                            await self.coordinator.release_coordination_lock(contract.execution_id)
                    else:
                        await self.coordinator.release_coordination_lock(contract.execution_id)

            # Re-enqueue if scheduling/dispatch failed
            self.queue_manager.enqueue(
                tenant_id=contract.tenant_id,
                item=contract,
                tenant_tier=tenant_tier,
                runtime_type=runtime_type,
                priority=priority
            )

        return scheduled_count
