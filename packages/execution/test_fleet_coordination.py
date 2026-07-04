import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch

from packages.execution.interfaces import ExecutionContract
from packages.execution.fleet import (
    FleetRegistry,
    RuntimeNode,
    InMemoryReservationStore,
    RedisReservationStore
)
from packages.execution.isolation import IsolationLevel, DefaultIsolationMatchPolicy
from packages.execution.quotas import (
    InMemoryTenantQuotaStore,
    DatabaseTenantQuotaStore,
    CachedTenantQuotaStore,
    TenantQuota,
    DefaultTenantQuotaPolicy
)
from packages.execution.queues import WorkloadQueueManager
from packages.execution.scheduler import FleetScheduler
from packages.execution.firecracker import ProductionFirecrackerPolicy
from packages.audit.emitter import audit_emitter

class TestFleetCoordination:
    @pytest.mark.asyncio
    async def test_reservation_claim_after_node_acknowledgment(self):
        # Setup registry and scheduler
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        scheduler = FleetScheduler(registry, quota_store)

        # Register node
        node = RuntimeNode(
            node_id="node1",
            tenant_scope="tenant1",
            runtime_types=["standard"],
            total_memory=1000,
            total_cpu=2.0
        )
        registry.register_node(node)

        # Create contract
        contract = ExecutionContract(
            contract_id="c1",
            execution_id="exec1",
            tenant_id="tenant1",
            workspace_id="w1",
            contract_version="1.0.0",
            target_node_id="node1",
            scheduler_id="sched1",
            scheduler_version="1.0.0",
            timestamp=time.time(),
            expires_at=time.time() + 60,
            nonce="n1",
            signature="sig1",
            image="img1",
            command=["run"],
            env={"REQUIRED_MEMORY": "500", "REQUIRED_CPU": "1.0"},
            capabilities=["filesystem:read"]
        )

        # 1. Schedule should create PENDING reservation
        success = await scheduler.schedule(contract)
        assert success is True

        # Check reservation exists and is pending
        res = await registry.reservation_store.get_reservation("exec1")
        assert res is not None
        assert res.status == "pending"
        assert res.scheduler_id == "sched1"
        assert res.tenant_id == "tenant1"

        # Capacity should be reserved, but not yet allocated on the node
        assert node.allocated_memory == 0
        assert node.allocated_cpu == 0.0

        # Check pending reservations for capacity policy
        pending = await registry.reservation_store.get_node_pending_reservations("node1")
        assert len(pending) == 1
        assert pending[0].execution_id == "exec1"

        # 2. Node acknowledges receipt -> transition to CLAIMED and allocate resources
        claim_success = await scheduler.acknowledge_node_receipt("exec1")
        assert claim_success is True

        res = await registry.reservation_store.get_reservation("exec1")
        assert res.status == "claimed"

        # Capacity is now officially allocated on the node
        assert node.allocated_memory == 500
        assert node.allocated_cpu == 1.0

        # Owner is durably assigned
        assert registry._ownerships["exec1"] == "node1"
        assert registry._execution_status["exec1"] == "acknowledged"

    @pytest.mark.asyncio
    async def test_reservation_expiration_reclaims_capacity(self):
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        scheduler = FleetScheduler(registry, quota_store)

        # Register node with tight capacity
        node = RuntimeNode(
            node_id="node1",
            tenant_scope="tenant1",
            runtime_types=["standard"],
            total_memory=500,
            total_cpu=1.0
        )
        registry.register_node(node)

        contract1 = ExecutionContract(
            contract_id="c1", execution_id="exec1", tenant_id="tenant1",
            workspace_id="w1", contract_version="1.0.0", target_node_id="node1",
            scheduler_id="sched1", scheduler_version="1.0.0", timestamp=time.time(),
            expires_at=time.time() + 60, nonce="n1", signature="sig1", image="img1",
            command=["run"], env={"REQUIRED_MEMORY": "400", "REQUIRED_CPU": "0.8"},
            capabilities=["filesystem:read"]
        )

        contract2 = ExecutionContract(
            contract_id="c2", execution_id="exec2", tenant_id="tenant1",
            workspace_id="w1", contract_version="1.0.0", target_node_id="node1",
            scheduler_id="sched1", scheduler_version="1.0.0", timestamp=time.time(),
            expires_at=time.time() + 60, nonce="n2", signature="sig2", image="img1",
            command=["run"], env={"REQUIRED_MEMORY": "200", "REQUIRED_CPU": "0.4"},
            capabilities=["filesystem:read"]
        )

        # First contract reserves 400 MB, leaving 100 MB remaining
        success1 = await scheduler.schedule(contract1)
        assert success1 is True

        # Second contract requires 200 MB, which exceeds remaining 100 MB. It should be queued.
        success2 = await scheduler.schedule(contract2)
        assert success2 is False
        assert scheduler.queue_manager.get_queue_depth("tenant1") == 1

        # Mock time moving forward past TTL (10 seconds)
        now = time.time()
        with patch("time.time", return_value=now + 15):
            # Expired reservations are naturally ignored by the capacity policy check
            # but cleanup_expired_reservations emits audit events
            expired_ids = await registry.reservation_store.cleanup_expired_reservations()
            assert "exec1" in expired_ids

            res = await registry.reservation_store.get_reservation("exec1")
            assert res.status == "expired"

            # Node capacity is reclaimed automatically
            # Let's process the queue, which should now successfully schedule contract2
            scheduled = await scheduler.process_queue()
            assert scheduled == 1
            assert scheduler.queue_manager.get_queue_depth("tenant1") == 0

            # Verify contract2 is scheduled (pending state, waiting for ack)
            res2 = await registry.reservation_store.get_reservation("exec2")
            assert res2 is not None
            assert res2.status == "pending"

    @pytest.mark.asyncio
    async def test_prevention_of_stale_reservation_double_claim(self):
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        scheduler = FleetScheduler(registry, quota_store)

        # Register node
        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0
        )
        registry.register_node(node)

        contract = ExecutionContract(
            contract_id="c1", execution_id="exec1", tenant_id="tenant1",
            workspace_id="w1", contract_version="1.0.0", target_node_id="node1",
            scheduler_id="sched1", scheduler_version="1.0.0", timestamp=time.time(),
            expires_at=time.time() + 60, nonce="n1", signature="sig1", image="img1",
            command=["run"], env={"REQUIRED_MEMORY": "500", "REQUIRED_CPU": "1.0"},
            capabilities=["filesystem:read"]
        )

        # Create reservation
        await scheduler.schedule(contract)

        # Claim works first time
        success = await scheduler.acknowledge_node_receipt("exec1")
        assert success is True

        # Claiming again fails (prevention of double claim)
        success_second = await scheduler.acknowledge_node_receipt("exec1")
        assert success_second is False

        # Release reservation
        await registry.reservation_store.release_reservation("exec1")
        
        # Claiming a released reservation fails
        success_after_release = await scheduler.acknowledge_node_receipt("exec1")
        assert success_after_release is False

    @pytest.mark.asyncio
    async def test_quota_cache_refresh_behavior(self):
        backing_store = InMemoryTenantQuotaStore()
        # Set specific quota config
        backing_store.set_quota(TenantQuota(
            tenant_id="tenant1",
            max_memory=1000,
            max_cpu=2.0,
            max_firecracker_slots=2,
            max_external_network_slots=2,
            max_queued_workloads=10,
            tenant_tier="premium"
        ))

        # Create Cached store with short TTL of 2 seconds
        cached_store = CachedTenantQuotaStore(backing_store, quota_cache_ttl_seconds=2)

        # 1. Fetch quota (Cache miss, hits DB/backing store)
        quota1 = await cached_store.get_quota("tenant1")
        assert quota1.max_memory == 1000
        assert cached_store.db_hits == 1

        # 2. Fetch again immediately (Cache hit, no DB hit)
        quota2 = await cached_store.get_quota("tenant1")
        assert quota2.max_memory == 1000
        assert cached_store.db_hits == 1

        # 3. Modify backing store but read within TTL
        backing_store.set_quota(TenantQuota(
            tenant_id="tenant1",
            max_memory=2000,
            max_cpu=4.0,
            max_firecracker_slots=4,
            max_external_network_slots=4,
            max_queued_workloads=20,
            tenant_tier="premium"
        ))
        quota3 = await cached_store.get_quota("tenant1")
        assert quota3.max_memory == 1000  # Still cached old value
        assert cached_store.db_hits == 1

        # 4. Explicit invalidation
        cached_store.invalidate("tenant1")
        quota_invalidated = await cached_store.get_quota("tenant1")
        assert quota_invalidated.max_memory == 2000  # Fetches updated value
        assert cached_store.db_hits == 2

        # 5. Wait for TTL to expire (mocked clock)
        now = time.time()
        backing_store.set_quota(TenantQuota(
            tenant_id="tenant1",
            max_memory=3000,
            max_cpu=6.0,
            max_firecracker_slots=6,
            max_external_network_slots=6,
            max_queued_workloads=30,
            tenant_tier="premium"
        ))
        
        with patch("time.time", return_value=now + 5):
            quota_expired = await cached_store.get_quota("tenant1")
            assert quota_expired.max_memory == 3000  # Refreshed after TTL expiry
            assert cached_store.db_hits == 3

    @pytest.mark.asyncio
    async def test_round_robin_tenant_dequeue_fairness(self):
        manager = WorkloadQueueManager(max_depth=10)

        # Enqueue A1, A2, A3 for tenant A
        manager.enqueue("tenantA", "A1", tenant_tier="standard")
        manager.enqueue("tenantA", "A2", tenant_tier="standard")
        manager.enqueue("tenantA", "A3", tenant_tier="standard")

        # Enqueue B1, B2 for tenant B
        manager.enqueue("tenantB", "B1", tenant_tier="standard")
        manager.enqueue("tenantB", "B2", tenant_tier="standard")

        # Dequeue in round-robin fashion
        seq = []
        for _ in range(5):
            seq.append(manager.dequeue())

        # Expected sequence: A1, B1, A2, B2, A3
        assert seq == ["A1", "B1", "A2", "B2", "A3"]

    @pytest.mark.asyncio
    async def test_backpressure_queue_rejection_limits(self):
        manager = WorkloadQueueManager(max_depth=2)

        # Enqueue up to max depth
        assert manager.enqueue("tenant1", "item1") is True
        assert manager.enqueue("tenant1", "item2") is True

        # Enqueuing 3rd item should fail (backpressure)
        assert manager.enqueue("tenant1", "item3") is False
        assert manager.get_queue_depth("tenant1") == 2

    @pytest.mark.asyncio
    async def test_audit_event_emissions(self):
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        policy = ProductionFirecrackerPolicy(
            jailer_enabled=True,
            benchmark_validation_completed=True,
            security_validation_completed=True,
            operational_runbook_completed=True,
            fleet_capability_explicitly_enabled=True
        )
        scheduler = FleetScheduler(registry, quota_store, production_firecracker_policy=policy)

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
            capabilities=["network:external"]  # Requires Firecracker isolation
        )

        mock_emit = AsyncMock()
        with patch.object(audit_emitter, "emit", mock_emit):
            # 1. Schedule should emit IsolationLevelSelected
            await scheduler.schedule(contract)
            
            # Check event calls
            emitted_names = [call.args[0].name for call in mock_emit.call_args_list]
            assert "IsolationLevelSelected" in emitted_names

            # Find IsolationLevelSelected details
            iso_event = next(call.args[0] for call in mock_emit.call_args_list if call.args[0].name == "IsolationLevelSelected")
            assert iso_event.payload["isolation_level"] == "firecracker"

            # 2. Release reservation should emit ReservationReleased
            mock_emit.reset_mock()
            await registry.reservation_store.release_reservation("exec1")
            
            emitted_names_release = [call.args[0].name for call in mock_emit.call_args_list]
            assert "ReservationReleased" in emitted_names_release
