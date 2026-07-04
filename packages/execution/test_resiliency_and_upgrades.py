import pytest
import asyncio
import time
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

from packages.events.envelope import EventEnvelope
from packages.events.redis_bus import RedisStreamEventBus
from packages.execution.interfaces import ExecutionContract
from packages.execution.fleet import FleetRegistry, RuntimeNode, InMemoryReservationStore
from packages.execution.lease import InMemoryLeaseManager
from packages.execution.quotas import InMemoryTenantQuotaStore
from packages.execution.scheduler import FleetScheduler
from packages.execution.reconciliation import OrphanReclamationManager, RollingUpgradeManager
from packages.observability.metrics import (
    lease_renewal_failure,
    regional_routing_rejection_count,
    orphan_recovery_quarantine_count,
    rolling_upgrade_drain_duration
)


class TestResiliencyAndUpgrades:

    @pytest.fixture
    def setup_registry_and_scheduler(self):
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        lease_manager = InMemoryLeaseManager()
        scheduler = FleetScheduler(
            registry=registry,
            quota_store=quota_store,
            lease_manager=lease_manager,
            scheduler_id="scheduler-active",
            lease_name="scheduler-leader"
        )
        return registry, scheduler, lease_manager

    def make_contract(self, exec_id="exec1", region=None, zone=None):
        return ExecutionContract(
            contract_id="c1",
            execution_id=exec_id,
            tenant_id="tenant1",
            workspace_id="w1",
            contract_version="1.0.0",
            target_node_id="node1",
            scheduler_id="scheduler-active",
            scheduler_version="1.0.0",
            timestamp=time.time(),
            expires_at=time.time() + 60,
            nonce="n1",
            signature="sig1",
            image="img1",
            command=["run"],
            env={"REQUIRED_MEMORY": "100", "REQUIRED_CPU": "0.5"},
            capabilities=["filesystem:read"],
            required_region=region,
            required_zone=zone
        )

    # 1. Lease Gating and Fail Closed Behavior
    @pytest.mark.asyncio
    async def test_scheduler_fails_closed_without_lease(self, setup_registry_and_scheduler):
        registry, scheduler, lease_manager = setup_registry_and_scheduler
        
        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0
        )
        registry.register_node(node)
        contract = self.make_contract()

        # Active scheduler does not hold lease -> should raise error
        with pytest.raises(RuntimeError) as exc:
            await scheduler.schedule(contract)
        assert "Not the active lease holder" in str(exc.value)

        # Now acquire lease
        await lease_manager.acquire_lease("scheduler-leader", "scheduler-active", 10.0)
        assert await scheduler.schedule(contract) is True

    @pytest.mark.asyncio
    async def test_lease_expiry_during_scheduling(self, setup_registry_and_scheduler):
        registry, scheduler, lease_manager = setup_registry_and_scheduler
        
        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0
        )
        registry.register_node(node)
        contract = self.make_contract()

        # Acquire lease with short duration
        await lease_manager.acquire_lease("scheduler-leader", "scheduler-active", 1.0)
        
        # Fast-forward time so lease expires
        with patch("time.time", return_value=time.time() + 2.0):
            with pytest.raises(RuntimeError) as exc:
                await scheduler.schedule(contract)
            assert "Not the active lease holder" in str(exc.value)

    @pytest.mark.asyncio
    async def test_split_brain_prevention(self, setup_registry_and_scheduler):
        registry, scheduler1, lease_manager = setup_registry_and_scheduler
        
        scheduler2 = FleetScheduler(
            registry=registry,
            quota_store=scheduler1.quota_store,
            lease_manager=lease_manager,
            scheduler_id="scheduler-passive",
            lease_name="scheduler-leader"
        )
        
        # Scheduler 1 acquires leader lease
        await lease_manager.acquire_lease("scheduler-leader", "scheduler-1", 10.0)
        
        # Scheduler 2 attempts to acquire -> fails because Scheduler 1 holds it
        success = await lease_manager.acquire_lease("scheduler-leader", "scheduler-2", 10.0)
        assert success is False

    # 2. Durable Consumer Groups and Event Replay Safety
    @pytest.mark.asyncio
    async def test_consumer_group_replay_and_acknowledgment(self):
        # We will mock Redis client calls in RedisStreamEventBus
        mock_redis = AsyncMock()
        bus = RedisStreamEventBus()
        bus._client = mock_redis

        # Mock xgroup_create
        mock_redis.xgroup_create = AsyncMock()
        # Mock xreadgroup to return pending, then new messages
        mock_redis.xreadgroup = AsyncMock()
        envelope = EventEnvelope(
            event_id="evt1", event_type="ScanStarted", trace_id="t1",
            correlation_id="c1", tenant_id="tenant1", timestamp=datetime.utcnow(),
            schema_version="1.0.0", source_context="scheduler", payload={}
        )
        serialized = bus._serialize_envelope(envelope)
        
        # First call returns one pending message
        # Second call returns empty to finish pending loop
        mock_redis.xreadgroup.side_effect = [
            [["topic1", [("1526569497161-0", {"envelope": serialized})]]],
            [],  # finishes pending loop
            [["topic1", [("1526569497162-0", {"envelope": serialized})]]] # new messages
        ]

        # Generator consumption
        gen = bus.subscribe_group("topic1", "group1", "consumer1")
        
        # Read first yielded message (the pending one)
        msg_id, rec_envelope = await gen.__anext__()
        assert msg_id == "1526569497161-0"
        assert rec_envelope.event_id == "evt1"

        # Acknowledge message
        mock_redis.xack = AsyncMock()
        await bus.acknowledge("topic1", "group1", msg_id)
        mock_redis.xack.assert_called_with("topic1", "group1", msg_id)

    @pytest.mark.asyncio
    async def test_claim_stuck_messages(self):
        mock_redis = AsyncMock()
        bus = RedisStreamEventBus()
        bus._client = mock_redis

        envelope = EventEnvelope(
            event_id="evt1", event_type="ScanStarted", trace_id="t1",
            correlation_id="c1", tenant_id="tenant1", timestamp=datetime.utcnow(),
            schema_version="1.0.0", source_context="scheduler", payload={}
        )
        serialized = bus._serialize_envelope(envelope)

        mock_redis.xpending_range.return_value = [
            {"message_id": "1-0", "consumer": "consumer-dead", "time_since_delivered": 10000, "times_delivered": 1}
        ]
        mock_redis.xclaim.return_value = [("1-0", {"envelope": serialized})]

        claimed = await bus.claim_stuck_messages("topic1", "group1", 5000, "consumer-active")
        assert len(claimed) == 1
        assert claimed[0][0] == "1-0"
        assert claimed[0][1].event_id == "evt1"
        mock_redis.xclaim.assert_called_with(
            name="topic1", groupname="group1", consumername="consumer-active", min_idle_time=5000, message_ids=["1-0"]
        )

    # 3. Explicit Multi-Region Workload Routing
    @pytest.mark.asyncio
    async def test_region_mismatch_and_fallback_denial(self, setup_registry_and_scheduler):
        registry, scheduler, lease_manager = setup_registry_and_scheduler
        await lease_manager.acquire_lease("scheduler-leader", "scheduler-active", 10.0)

        # Node in us-east-1
        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0, region="us-east-1"
        )
        registry.register_node(node)

        # Workload requires us-west-2
        contract = self.make_contract(region="us-west-2")

        # Scheduling should fail closed or queue because regions mismatch
        success = await scheduler.schedule(contract)
        assert success is False  # Queued due to capacity/routing mismatch

        # Verify that it is queued
        assert scheduler.queue_manager.get_queue_depth("tenant1") == 1

    # 4. Conservative Orphan Reclamation
    @pytest.mark.asyncio
    async def test_orphan_quarantine_on_ambiguity(self, setup_registry_and_scheduler):
        registry, scheduler, lease_manager = setup_registry_and_scheduler
        await lease_manager.acquire_lease("scheduler-leader", "scheduler-active", 10.0)

        # Create active node assignment
        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0, health_status="healthy"
        )
        registry.register_node(node)

        contract = self.make_contract(exec_id="exec_ambiguous")
        
        # Dispatch and claim reservation
        await scheduler.schedule(contract)
        await scheduler.acknowledge_node_receipt("exec_ambiguous")

        # Now simulate node goes offline
        node.health_status = "offline"

        # Reconciliation manager runs
        reclaimer = OrphanReclamationManager(
            registry=registry,
            scheduler=scheduler,
            lease_manager=lease_manager,
            scheduler_id="scheduler-active"
        )

        # Execution has side effects or reservation is claimed -> ambiguous to reclaim, must quarantine
        # By default, reservation state is 'claimed'
        await reclaimer.reclaim_orphans()

        # Status must be quarantined, not reassigned
        assert registry._execution_status["exec_ambiguous"] == "quarantined"

    @pytest.mark.asyncio
    async def test_safe_orphan_requeue(self, setup_registry_and_scheduler):
        registry, scheduler, lease_manager = setup_registry_and_scheduler
        await lease_manager.acquire_lease("scheduler-leader", "scheduler-active", 10.0)

        node = RuntimeNode(
            node_id="node1", tenant_scope="tenant1", runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0, health_status="healthy"
        )
        registry.register_node(node)

        contract = self.make_contract(exec_id="exec_safe")
        
        # Dispatch (reservation created but NOT claimed/acknowledged yet)
        await scheduler.schedule(contract)

        # Node goes offline
        node.health_status = "offline"

        reclaimer = OrphanReclamationManager(
            registry=registry,
            scheduler=scheduler,
            lease_manager=lease_manager,
            scheduler_id="scheduler-active"
        )

        # Safe to requeue because reservation is pending and no side-effects
        await reclaimer.reclaim_orphans()

        # Status should be released and contract re-queued
        assert registry._execution_status["exec_safe"] == "released"
        assert scheduler.queue_manager.get_queue_depth("tenant1") == 1

    # 5. Graceful Rolling Node Upgrade Flow
    @pytest.mark.asyncio
    async def test_drain_based_upgrade_flow(self, setup_registry_and_scheduler):
        registry, scheduler, lease_manager = setup_registry_and_scheduler
        await lease_manager.acquire_lease("scheduler-leader", "scheduler-active", 10.0)

        # Node running older version
        node = RuntimeNode(
            node_id="node_upgrade", tenant_scope="tenant1", runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0, software_version="0.9.0"
        )
        registry.register_node(node)

        upgrader = RollingUpgradeManager(
            registry=registry,
            scheduler=scheduler,
            target_version="1.0.0",
            lease_manager=lease_manager,
            scheduler_id="scheduler-active"
        )

        # First pass: identifies outdated node and drains it
        await upgrader.orchestrate_upgrades()
        assert node.health_status == "draining"

        # Simulate active work on node (allocating resource)
        await registry.allocate_resources("node_upgrade", 100, 0.5)
        
        # Second pass: node is still draining because allocations > 0
        await upgrader.orchestrate_upgrades()
        assert node.health_status == "draining"
        assert node.software_version == "0.9.0"

        # Release resources (active work finishes)
        await registry.release_resources("node_upgrade", 100, 0.5)

        # Third pass: allocations reach zero, node upgraded and rejoins
        await upgrader.orchestrate_upgrades()
        assert node.health_status == "healthy"
        assert node.software_version == "1.0.0"
