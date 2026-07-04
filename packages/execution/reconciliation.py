import json
import time
import logging
import asyncio
from typing import List, Dict, Set, Optional, Any

logger = logging.getLogger(__name__)

class DockerReconciliationManager:
    """
    Manages two-pass reconciliation and cleanup of orphaned tenant bridge networks.
    If container inspection is ambiguous or fails, deletion must not occur.
    """

    def __init__(self, run_cmd_fn=None, grace_period_sec: float = 5.0):
        self._run_cmd = run_cmd_fn or self._default_run_cmd
        self.grace_period_sec = grace_period_sec
        # Maps network_name -> marked_timestamp
        self.candidate_orphaned_networks: Dict[str, float] = {}

    async def _default_run_cmd(self, args: List[str]) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_bytes, stderr_bytes = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(stderr_bytes.decode("utf-8", errors="replace"))
            return stdout_bytes.decode("utf-8", errors="replace")
        except FileNotFoundError:
            raise RuntimeError("CLI executable not found")

    async def reconcile(self) -> None:
        """
        Executes a reconciliation pass.
        1. Lists all sentinel-net-* networks.
        2. Lists all container IDs.
        3. Inspects containers. Hard abort on inspect failure to prevent orphan deletion.
        4. Identifies unused networks.
        5. Performs two-pass confirmation before deletion.
        """
        logger.info("Starting two-pass network reconciliation...")
        try:
            # 1. Get sentinel networks
            net_out = await self._run_cmd(["docker", "network", "ls", "--filter", "name=sentinel-net-", "--format", "{{.Name}}"])
            sentinel_nets = [line.strip() for line in net_out.splitlines() if line.strip()]
            if not sentinel_nets:
                logger.info("No sentinel networks found.")
                self.candidate_orphaned_networks.clear()
                return

            # 2. Get all container IDs
            container_out = await self._run_cmd(["docker", "ps", "-a", "-q"])
            container_ids = [line.strip() for line in container_out.splitlines() if line.strip()]

            # 3. Inspect containers and track active networks
            active_nets: Set[str] = set()
            for cid in container_ids:
                try:
                    inspect_out = await self._run_cmd(["docker", "inspect", cid])
                    inspect_data = json.loads(inspect_out)
                    if not inspect_data:
                        logger.warning(f"Empty inspect data for container {cid}. Treating as ambiguous.")
                        return  # Conservative: abort reconciliation pass

                    state = inspect_data[0].get("State", {})
                    status = state.get("Status", "").lower()

                    # Keep networks for active container states (running, paused, restarting)
                    if status in ("running", "paused", "restarting"):
                        net_settings = inspect_data[0].get("NetworkSettings", {})
                        networks = net_settings.get("Networks", {})
                        for net_name in networks.keys():
                            active_nets.add(net_name)

                except Exception as e:
                    logger.error(f"Failed to inspect container {cid} gracefully: {e}. Aborting pass for safety.")
                    # Conservative inspect failure policy: abort execution to avoid removing active networks
                    return

            # 4. Process unused networks
            current_time = time.time()
            unused_nets = [net for net in sentinel_nets if net not in active_nets]

            # Reconcile candidates
            new_candidates: Dict[str, float] = {}
            for net in unused_nets:
                if net in self.candidate_orphaned_networks:
                    # Network was marked in a previous pass
                    marked_time = self.candidate_orphaned_networks[net]
                    if current_time - marked_time >= self.grace_period_sec:
                        # Confirmed orphan (Pass 2) — safe to delete
                        logger.warning(f"[AUDIT] Removing confirmed orphaned network: {net}")
                        try:
                            await self._run_cmd(["docker", "network", "rm", net])
                            logger.info(f"[AUDIT] Successfully removed network {net}")
                        except Exception as e:
                            logger.error(f"Failed to remove network {net}: {e}")
                    else:
                        # Keep candidate until grace period expires
                        new_candidates[net] = marked_time
                else:
                    # Mark candidate (Pass 1)
                    logger.info(f"Marking candidate orphaned network: {net}")
                    new_candidates[net] = current_time

            self.candidate_orphaned_networks = new_candidates

        except Exception as e:
            logger.error(f"Critical error during reconciliation: {e}")


class OrphanReclamationManager:
    """
    Coordinates passive/active recovery roles for orphaned executions.
    Only the active leaseholder can perform reclamation.
    """
    def __init__(
        self,
        registry: Any,
        scheduler: Any,
        lease_manager: Optional[Any] = None,
        scheduler_id: str = "scheduler-default",
        lease_name: str = "scheduler-leader"
    ):
        self.registry = registry
        self.scheduler = scheduler
        self.lease_manager = lease_manager
        self.scheduler_id = scheduler_id
        self.lease_name = lease_name

    async def reclaim_orphans(self) -> None:
        if self.lease_manager:
            is_leader = await self.lease_manager.is_lease_active(self.lease_name, self.scheduler_id)
            if not is_leader:
                logger.info(f"OrphanReclamationManager on scheduler {self.scheduler_id} is passive: skipping reclamation.")
                return

        # Trigger node health status checks (offline transition)
        await self.registry.get_healthy_nodes("default")

        processed = set()

        for exec_id, node_id in list(self.registry._ownerships.items()):
            status = self.registry._execution_status.get(exec_id)
            if status in ("completed", "released", "expired", "quarantined"):
                continue

            node = self.registry._nodes.get(node_id)
            if not node or node.health_status in ("offline", "quarantined"):
                processed.add(exec_id)
                has_side_effects = self.registry._execution_has_side_effects.get(exec_id, False)
                reservation = await self.registry.reservation_store.get_reservation(exec_id)

                is_safe_to_requeue = (
                    reservation is not None
                    and reservation.status == "pending"
                    and not has_side_effects
                    and node is not None
                )

                if is_safe_to_requeue:
                    logger.info(f"OrphanReclamationManager: requeuing safe execution {exec_id}")
                    contract = self.scheduler._contracts.get(exec_id)
                    if contract:
                        memory = int(contract.env.get("REQUIRED_MEMORY", contract.env.get("memory", 128)))
                        cpu = float(contract.env.get("REQUIRED_CPU", contract.env.get("cpu", 0.1)))
                        priority = contract.env.get("PRIORITY", contract.env.get("priority", "low"))
                        isolation_level = await self.scheduler.isolation_policy.required_isolation(set(contract.capabilities))
                        
                        quota = await self.scheduler.quota_store.get_quota(contract.tenant_id)
                        tenant_tier = getattr(quota, "tenant_tier", "standard")
                        runtime_type = isolation_level.value

                        self.scheduler.queue_manager.enqueue(
                            tenant_id=contract.tenant_id,
                            item=contract,
                            tenant_tier=tenant_tier,
                            runtime_type=runtime_type,
                            priority=priority
                        )
                        await self.registry.reservation_store.release_reservation(exec_id, "Reclaimed and requeued")
                        self.registry._execution_status[exec_id] = "released"
                    else:
                        logger.warning(f"OrphanReclamationManager: contract missing for {exec_id}. Quarantining.")
                        self.registry._execution_status[exec_id] = "quarantined"
                        from packages.observability.metrics import orphan_recovery_quarantine_count
                        orphan_recovery_quarantine_count.add(1)
                        await self.registry.reservation_store.release_reservation(exec_id, "Quarantined: contract missing")
                else:
                    logger.warning(f"OrphanReclamationManager: quarantining execution {exec_id} due to ambiguity/claimed reservation/side-effects.")
                    self.registry._execution_status[exec_id] = "quarantined"
                    from packages.observability.metrics import orphan_recovery_quarantine_count
                    orphan_recovery_quarantine_count.add(1)
                    await self.registry.reservation_store.release_reservation(exec_id, "Quarantined due to orphan recovery ambiguity")

        for node in list(self.registry._nodes.values()):
            if node.health_status in ("offline", "quarantined"):
                pending = await self.registry.reservation_store.get_node_pending_reservations(node.node_id)
                for res in pending:
                    exec_id = res.execution_id
                    if exec_id in processed:
                        continue
                    processed.add(exec_id)
                    has_side_effects = self.registry._execution_has_side_effects.get(exec_id, False)

                    is_safe_to_requeue = not has_side_effects
                    if is_safe_to_requeue:
                        logger.info(f"OrphanReclamationManager: requeuing safe pending execution {exec_id}")
                        contract = self.scheduler._contracts.get(exec_id)
                        if contract:
                            memory = int(contract.env.get("REQUIRED_MEMORY", contract.env.get("memory", 128)))
                            cpu = float(contract.env.get("REQUIRED_CPU", contract.env.get("cpu", 0.1)))
                            priority = contract.env.get("PRIORITY", contract.env.get("priority", "low"))
                            isolation_level = await self.scheduler.isolation_policy.required_isolation(set(contract.capabilities))
                            
                            quota = await self.scheduler.quota_store.get_quota(contract.tenant_id)
                            tenant_tier = getattr(quota, "tenant_tier", "standard")
                            runtime_type = isolation_level.value

                            self.scheduler.queue_manager.enqueue(
                                tenant_id=contract.tenant_id,
                                item=contract,
                                tenant_tier=tenant_tier,
                                runtime_type=runtime_type,
                                priority=priority
                            )
                            await self.registry.reservation_store.release_reservation(exec_id, "Reclaimed and requeued")
                            self.registry._execution_status[exec_id] = "released"
                        else:
                            self.registry._execution_status[exec_id] = "quarantined"
                            from packages.observability.metrics import orphan_recovery_quarantine_count
                            orphan_recovery_quarantine_count.add(1)
                            await self.registry.reservation_store.release_reservation(exec_id, "Quarantined: contract missing")
                    else:
                        logger.warning(f"OrphanReclamationManager: quarantining pending execution {exec_id} due to side-effects.")
                        self.registry._execution_status[exec_id] = "quarantined"
                        from packages.observability.metrics import orphan_recovery_quarantine_count
                        orphan_recovery_quarantine_count.add(1)
                        await self.registry.reservation_store.release_reservation(exec_id, "Quarantined due to orphan recovery ambiguity")


class RollingUpgradeManager:
    """
    Orchestrates node drain and version upgrades.
    Only the active leaseholder can orchestrate upgrades.
    """
    def __init__(
        self,
        registry: Any,
        scheduler: Any,
        target_version: str = "1.0.0",
        lease_manager: Optional[Any] = None,
        scheduler_id: str = "scheduler-default",
        lease_name: str = "scheduler-leader"
    ):
        self.registry = registry
        self.scheduler = scheduler
        self.target_version = target_version
        self.lease_manager = lease_manager
        self.scheduler_id = scheduler_id
        self.lease_name = lease_name
        self._drain_start_times: Dict[str, float] = {}

    async def orchestrate_upgrades(self) -> None:
        if self.lease_manager:
            is_leader = await self.lease_manager.is_lease_active(self.lease_name, self.scheduler_id)
            if not is_leader:
                logger.info(f"RollingUpgradeManager on scheduler {self.scheduler_id} is passive: skipping upgrades.")
                return

        just_drained = set()
        for node in list(self.registry._nodes.values()):
            if node.software_version != self.target_version:
                if node.health_status not in ("draining", "offline", "quarantined"):
                    logger.info(f"RollingUpgradeManager: transitioning outdated node {node.node_id} (version {node.software_version}) to draining")
                    self.registry.drain_node(node.node_id)
                    self._drain_start_times[node.node_id] = time.time()
                    just_drained.add(node.node_id)

        for node_id in list(self._drain_start_times.keys()):
            if node_id in just_drained:
                continue

            node = self.registry._nodes.get(node_id)
            if not node:
                self._drain_start_times.pop(node_id, None)
                continue

            pending_res = await self.registry.reservation_store.get_node_pending_reservations(node_id)
            if node.allocated_memory == 0 and node.allocated_cpu == 0.0 and len(pending_res) == 0:
                logger.info(f"RollingUpgradeManager: node {node_id} reaches zero allocations. Upgrading to {self.target_version}")
                node.software_version = self.target_version
                node.health_status = "healthy"  # rejoin
                node.last_heartbeat = time.time()  # update heartbeat

                drain_start = self._drain_start_times.pop(node_id, time.time())
                duration = time.time() - drain_start
                from packages.observability.metrics import rolling_upgrade_drain_duration
                rolling_upgrade_drain_duration.record(duration)
