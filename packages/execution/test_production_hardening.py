import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch

from packages.execution.interfaces import ExecutionContract
from packages.execution.fleet import (
    FleetRegistry,
    RuntimeNode,
    InMemoryReservationStore,
    StrictOneToOneCapacityPolicy
)
from packages.execution.isolation import IsolationLevel, DefaultIsolationMatchPolicy
from packages.execution.quotas import InMemoryTenantQuotaStore
from packages.execution.queues import WorkloadQueueManager
from packages.execution.firecracker import ProductionFirecrackerPolicy, FirecrackerRuntime
from packages.execution.ha import SimpleDatabaseHealthProvider, ActiveActiveCoordinator
from packages.execution.scheduler import FleetScheduler
from packages.execution.autoscaler import FleetAutoscaler

class TestProductionHardening:
    @pytest.fixture(autouse=True)
    def clean_locks(self):
        ActiveActiveCoordinator._shared_local_locks.clear()

    @pytest.mark.asyncio
    async def test_firecracker_production_gate_enforcement(self):
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        
        # 1. Gates disabled by default
        policy = ProductionFirecrackerPolicy()
        assert policy.is_eligible() is False

        scheduler = FleetScheduler(
            registry=registry,
            quota_store=quota_store,
            production_firecracker_policy=policy
        )

        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", runtime_types=["firecracker"],
            total_memory=1000, total_cpu=2.0
        )
        registry.register_node(node)

        contract = ExecutionContract(
            contract_id="c1", execution_id="exec1", tenant_id="tenant1",
            workspace_id="w1", contract_version="1.0.0", target_node_id="node1",
            scheduler_id="sched1", scheduler_version="1.0.0", timestamp=time.time(),
            expires_at=time.time() + 60, nonce="n1", signature="sig1", image="img1",
            command=["run"], env={"REQUIRED_MEMORY": "100", "REQUIRED_CPU": "0.5"},
            capabilities=["network:external"]  # Requires Firecracker
        )

        # Should fail closed because gates are not met
        with pytest.raises(ValueError) as exc:
            await scheduler.schedule(contract)
        assert "production readiness gates not met" in str(exc.value)

        # 2. Enable policy gates
        policy_passed = ProductionFirecrackerPolicy(
            jailer_enabled=True,
            benchmark_validation_completed=True,
            security_validation_completed=True,
            operational_runbook_completed=True,
            fleet_capability_explicitly_enabled=True
        )
        assert policy_passed.is_eligible() is True

        scheduler_passed = FleetScheduler(
            registry=registry,
            quota_store=quota_store,
            production_firecracker_policy=policy_passed
        )

        # Should succeed now
        success = await scheduler_passed.schedule(contract)
        assert success is True

    @pytest.mark.asyncio
    async def test_firecracker_benchmark_limits(self):
        # Memory boundary: 128 to 1024, CPU boundary: 1 to 4
        runtime = FirecrackerRuntime()

        # Under limits: fails
        res1 = await runtime.execute(
            image="", command=["run"], env={},
            capabilities=["memory:64m", "cpu:1"]
        )
        assert res1.exit_code == -1
        assert "violates benchmark boundaries" in res1.stderr

        # Over limits: fails
        res2 = await runtime.execute(
            image="", command=["run"], env={},
            capabilities=["memory:2048m", "cpu:2"]
        )
        assert res2.exit_code == -1
        assert "violates benchmark boundaries" in res2.stderr

    @pytest.mark.asyncio
    async def test_autoscaler_hysteresis_and_recommendations(self):
        registry = FleetRegistry()
        queue_manager = WorkloadQueueManager()

        # Setup autoscaler: requires 3 intervals to scale up, 10s cooldown to scale down
        autoscaler = FleetAutoscaler(
            registry=registry,
            queue_manager=queue_manager,
            scale_up_intervals=3,
            scale_down_cooldown=10.0,
            min_nodes=1,
            max_nodes=5
        )

        # Add node to registry
        node1 = RuntimeNode(
            node_id="n1", total_memory=1000, total_cpu=2.0,
            allocated_memory=0, allocated_cpu=0.0
        )
        registry.register_node(node1)

        # 1. Set high utilization (utilization = 90%)
        node1.allocated_memory = 900
        
        # Check 1: Should not trigger scale_up yet (hysteresis)
        rec1 = await autoscaler.evaluate()
        assert rec1 is not None
        assert rec1.recommendation_type == "none"

        # Check 2: Still none
        rec2 = await autoscaler.evaluate()
        assert rec2 is None  # None because it is deduplicated (identical to previous 'none' recommendation)

        # Check 3 (consecutive check 3): scale_up should be recommended
        # We manually bypass deduplication by calling evaluate under incremented interval
        autoscaler._consecutive_scale_up_checks = 2  # Pretend it is the 3rd check
        rec3 = await autoscaler.evaluate()
        assert rec3 is not None
        assert rec3.recommendation_type == "scale_up"
        assert rec3.desired_node_count == 2

        # Check 4: identical scale_up should be deduplicated / suppressed
        rec4 = await autoscaler.evaluate()
        assert rec4 is None

        # 2. Cooldown check for scale down
        node1.allocated_memory = 0  # 0% utilization
        # Register a second node to allow scaling down
        node2 = RuntimeNode(node_id="n2", total_memory=1000, total_cpu=2.0)
        registry.register_node(node2)

        # Check immediately: no scale down because cooldown window hasn't passed
        rec5 = await autoscaler.evaluate()
        assert rec5 is not None
        assert rec5.recommendation_type == "none"

        # Mock time forward by 15 seconds (cooldown is 10s)
        now = time.time()
        with patch("time.time", return_value=now + 15):
            rec6 = await autoscaler.evaluate()
            assert rec6 is not None
            assert rec6.recommendation_type == "scale_down"
            assert rec6.desired_node_count == 1

    @pytest.mark.asyncio
    async def test_tenant_local_tail_drop_enforcement(self):
        manager = WorkloadQueueManager(max_depth=2)

        # Enqueue A1 (low), A2 (medium) for Tenant A
        assert manager.enqueue("tenantA", "A1", priority="low") is True
        assert manager.enqueue("tenantA", "A2", priority="medium") is True

        # Enqueue B1 (low) for Tenant B
        assert manager.enqueue("tenantB", "B1", priority="low") is True

        # Enqueue A3 (high) for Tenant A -> should trigger local tail-drop evicting A1
        assert manager.enqueue("tenantA", "A3", priority="high") is True

        # Verify Tenant A's depth remains 2 (A2, A3)
        assert manager.get_queue_depth("tenantA") == 2
        # Verify Tenant B's queue is completely untouched (tenant isolation)
        assert manager.get_queue_depth("tenantB") == 1

        # Trying to enqueue A4 (low) should be rejected (not higher than lowest: medium/high)
        assert manager.enqueue("tenantA", "A4", priority="low") is False

    @pytest.mark.asyncio
    async def test_priority_ordering_and_fifo_with_fairness(self):
        manager = WorkloadQueueManager(max_depth=10)

        # Tenant A: A1 (low), A2 (high), A3 (medium), A4 (high)
        # Note: A2 is older than A4
        manager.enqueue("tenantA", "A1", priority="low")
        manager.enqueue("tenantA", "A2", priority="high")
        manager.enqueue("tenantA", "A3", priority="medium")
        manager.enqueue("tenantA", "A4", priority="high")

        # Tenant B: B1 (medium), B2 (high)
        manager.enqueue("tenantB", "B1", priority="medium")
        manager.enqueue("tenantB", "B2", priority="high")

        # Dequeue verification
        # 1. Tenant A -> should pop A2 (high, oldest)
        assert manager.dequeue() == "A2"
        # 2. Tenant B -> should pop B2 (high)
        assert manager.dequeue() == "B2"
        # 3. Tenant A -> should pop A4 (high)
        assert manager.dequeue() == "A4"
        # 4. Tenant B -> should pop B1 (medium)
        assert manager.dequeue() == "B1"
        # 5. Tenant A -> should pop A3 (medium)
        assert manager.dequeue() == "A3"
        # 6. Tenant A -> should pop A1 (low)
        assert manager.dequeue() == "A1"

    @pytest.mark.asyncio
    async def test_coordinator_lock_loss_recovery(self):
        ActiveActiveCoordinator._shared_local_locks.clear()
        store = InMemoryReservationStore()
        registry = FleetRegistry(reservation_store=store)

        # Two coordinators simulating active-active schedulers
        coord1 = ActiveActiveCoordinator(store)
        coord2 = ActiveActiveCoordinator(store)

        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", total_memory=1000, total_cpu=2.0
        )
        registry.register_node(node)

        # Scheduler 1 acquires coordination lock and creates reservation
        lock1 = await coord1.acquire_coordination_lock("exec1")
        assert lock1 is True

        res1 = await store.create_reservation(
            reservation_id="res1", execution_id="exec1", node_id="node1",
            scheduler_id="sched1", tenant_id="tenant1", memory=500, cpu=1.0, ttl_seconds=10
        )
        assert res1 is True

        # Scheduler 2 lock collision occurs
        lock2 = await coord2.acquire_coordination_lock("exec1")
        assert lock2 is False  # Lock optimization prevents Scheduler 2 from trying

        # Lock loss simulation: Scheduler 2 tries to reserve anyway (lock client fail / bypass)
        # ReservationStore should authoritatively reject it (SET NX protection)
        res2 = await store.create_reservation(
            reservation_id="res2", execution_id="exec1", node_id="node1",
            scheduler_id="sched2", tenant_id="tenant1", memory=500, cpu=1.0, ttl_seconds=10
        )
        assert res2 is False  # Atomic reservation store protects correct ownership

    @pytest.mark.asyncio
    async def test_database_health_boundaries(self):
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        db_health = SimpleDatabaseHealthProvider("healthy")

        scheduler = FleetScheduler(
            registry=registry,
            quota_store=quota_store,
            db_health_provider=db_health
        )

        contract = ExecutionContract(
            contract_id="c1", execution_id="exec1", tenant_id="tenant1",
            workspace_id="w1", contract_version="1.0.0", target_node_id="node1",
            scheduler_id="sched1", scheduler_version="1.0.0", timestamp=time.time(),
            expires_at=time.time() + 60, nonce="n1", signature="sig1", image="img1",
            command=["run"], env={"REQUIRED_MEMORY": "100", "REQUIRED_CPU": "0.5"},
            capabilities=["filesystem:read"]
        )

        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0
        )
        registry.register_node(node)

        # 1. Healthy operation
        assert await scheduler.schedule(contract) is True

        # 2. Degraded operation continues
        db_health.set_state("degraded")
        contract2 = ExecutionContract(
            contract_id="c2", execution_id="exec2", tenant_id="tenant1",
            workspace_id="w1", contract_version="1.0.0", target_node_id="node1",
            scheduler_id="sched1", scheduler_version="1.0.0", timestamp=time.time(),
            expires_at=time.time() + 60, nonce="n2", signature="sig2", image="img1",
            command=["run"], env={"REQUIRED_MEMORY": "100", "REQUIRED_CPU": "0.5"},
            capabilities=["filesystem:read"]
        )
        assert await scheduler.schedule(contract2) is True

        # 3. Unavailable fails closed
        db_health.set_state("unavailable")
        contract3 = ExecutionContract(
            contract_id="c3", execution_id="exec3", tenant_id="tenant1",
            workspace_id="w1", contract_version="1.0.0", target_node_id="node1",
            scheduler_id="sched1", scheduler_version="1.0.0", timestamp=time.time(),
            expires_at=time.time() + 60, nonce="n3", signature="sig3", image="img1",
            command=["run"], env={"REQUIRED_MEMORY": "100", "REQUIRED_CPU": "0.5"},
            capabilities=["filesystem:read"]
        )
        with pytest.raises(RuntimeError) as exc:
            await scheduler.schedule(contract3)
        assert "Database unavailable" in str(exc.value)
