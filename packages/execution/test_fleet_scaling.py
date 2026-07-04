import pytest
import asyncio
import time
from unittest.mock import patch

from packages.execution.fleet import (
    FleetRegistry,
    RuntimeNode,
    StrictOneToOneCapacityPolicy
)
from packages.execution.isolation import (
    IsolationLevel,
    DefaultIsolationMatchPolicy
)
from packages.observability.metrics import FleetMetricsCollector

class TestResourceAccounting:
    @pytest.mark.asyncio
    async def test_atomic_allocation_and_release(self):
        registry = FleetRegistry()
        node = RuntimeNode(
            node_id="n1", tenant_scope="tenant1", runtime_types=["docker"],
            total_memory=1024, total_cpu=2.0
        )
        registry.register_node(node)

        # 1. Allocate within limits
        success = await registry.allocate_resources("n1", 512, 1.0)
        assert success is True
        assert registry._nodes["n1"].allocated_memory == 512
        assert registry._nodes["n1"].allocated_cpu == 1.0

        # 2. Release resources
        await registry.release_resources("n1", 256, 0.5)
        assert registry._nodes["n1"].allocated_memory == 256
        assert registry._nodes["n1"].allocated_cpu == 0.5

        # 3. Idempotent release (should not drop below zero)
        await registry.release_resources("n1", 1000, 2.0)
        assert registry._nodes["n1"].allocated_memory == 0
        assert registry._nodes["n1"].allocated_cpu == 0.0

    @pytest.mark.asyncio
    async def test_allocation_overflow_prevention(self):
        registry = FleetRegistry()
        node = RuntimeNode(
            node_id="n1", tenant_scope="tenant1", runtime_types=["docker"],
            total_memory=512, total_cpu=1.0
        )
        registry.register_node(node)

        # 1. Allocate exact capacity
        assert await registry.allocate_resources("n1", 512, 1.0) is True

        # 2. Over commit should be blocked (strict 1:1)
        assert await registry.allocate_resources("n1", 1, 0.0) is False
        assert await registry.allocate_resources("n1", 0, 0.1) is False

    @pytest.mark.asyncio
    async def test_concurrent_allocation_safety(self):
        registry = FleetRegistry()
        node = RuntimeNode(
            node_id="n1", tenant_scope="tenant1", runtime_types=["docker"],
            total_memory=1000, total_cpu=10.0
        )
        registry.register_node(node)

        # Run 10 parallel allocations of 100MB and 1.0 CPU
        async def allocate_task():
            return await registry.allocate_resources("n1", 100, 1.0)

        results = await asyncio.gather(*(allocate_task() for _ in range(10)))
        assert all(results) is True
        assert registry._nodes["n1"].allocated_memory == 1000
        assert registry._nodes["n1"].allocated_cpu == 10.0

        # Next one fails
        assert await registry.allocate_resources("n1", 100, 1.0) is False

class TestHealthDegradation:
    @pytest.mark.asyncio
    async def test_healthy_degraded_offline_transitions(self):
        registry = FleetRegistry()
        node = RuntimeNode(node_id="n1", tenant_scope="t1")
        registry.register_node(node)

        with patch("time.time") as mock_time:
            # 1. Healthy (last heartbeat is current time)
            mock_time.return_value = 1000.0
            node.last_heartbeat = 1000.0
            healthy_list = await registry.get_healthy_nodes("t1")
            assert len(healthy_list) == 1
            assert node.health_status == "healthy"

            # 2. Degraded (> 15 seconds without heartbeat)
            mock_time.return_value = 1016.0
            healthy_list = await registry.get_healthy_nodes("t1")
            # Degraded nodes are still returned as candidates but status updates
            assert len(healthy_list) == 1
            assert node.health_status == "degraded"

            # 3. Offline (> 30 seconds without heartbeat)
            mock_time.return_value = 1031.0
            healthy_list = await registry.get_healthy_nodes("t1")
            # Offline nodes are excluded
            assert len(healthy_list) == 0
            assert node.health_status == "offline"

    @pytest.mark.asyncio
    async def test_health_transitions_do_not_clear_workloads(self):
        registry = FleetRegistry()
        node = RuntimeNode(node_id="n1", tenant_scope="t1")
        registry.register_node(node)

        # Assign a task
        await registry.assign_execution("exec1", "n1", memory=100, cpu=0.1)
        assert registry._ownerships["exec1"] == "n1"

        # Force node to offline via elapsed heartbeat time
        now = time.time()
        with patch("time.time") as mock_time:
            mock_time.return_value = now + 40.0
            # Query healthy list to trigger dynamic health check update
            await registry.get_healthy_nodes("t1")
            assert node.health_status == "offline"

            # Active workload must NOT be cleared automatically (prevents duplicate execution)
            assert "exec1" in registry._ownerships
            assert registry._ownerships["exec1"] == "n1"

class TestIsolationRouting:
    @pytest.mark.asyncio
    async def test_isolation_matching_policy(self):
        policy = DefaultIsolationMatchPolicy()
        
        # 1. Standard isolation
        assert await policy.required_isolation(set()) == IsolationLevel.STANDARD
        assert await policy.required_isolation({"filesystem:read"}) == IsolationLevel.STANDARD

        # 2. gVisor isolation
        assert await policy.required_isolation({"filesystem:write"}) == IsolationLevel.GVISOR
        assert await policy.required_isolation({"filesystem:read", "filesystem:write"}) == IsolationLevel.GVISOR

        # 3. Firecracker isolation
        assert await policy.required_isolation({"network:external"}) == IsolationLevel.FIRECRACKER
        assert await policy.required_isolation({"network:external", "filesystem:write"}) == IsolationLevel.FIRECRACKER

    @pytest.mark.asyncio
    async def test_scheduler_node_selection_by_isolation_and_capacity(self):
        registry = FleetRegistry()
        
        # Node 1: supports standard docker, low capacity
        node1 = RuntimeNode(
            node_id="n1", tenant_scope="t1", runtime_types=["docker"],
            total_memory=256, total_cpu=0.5
        )
        # Node 2: supports firecracker, high capacity
        node2 = RuntimeNode(
            node_id="n2", tenant_scope="t1", runtime_types=["firecracker"],
            total_memory=1024, total_cpu=2.0
        )
        registry.register_node(node1)
        registry.register_node(node2)

        # 1. Request STANDARD docker runtime with low capacity -> selects Node 1
        sel1 = await registry.select_node(required_runtime="docker", tenant_id="t1", required_memory=128, required_cpu=0.1)
        assert sel1 is not None
        assert sel1.node_id == "n1"

        # 2. Request STANDARD docker runtime but exceeding Node 1 capacity -> selects None
        sel2 = await registry.select_node(required_runtime="docker", tenant_id="t1", required_memory=512, required_cpu=1.0)
        assert sel2 is None

        # 3. Request FIRECRACKER runtime -> selects Node 2
        sel3 = await registry.select_node(required_runtime="firecracker", tenant_id="t1", required_memory=512, required_cpu=1.0)
        assert sel3 is not None
        assert sel3.node_id == "n2"

class TestDrainingTimeout:
    @pytest.mark.asyncio
    async def test_draining_grace_period_and_timeouts(self):
        registry = FleetRegistry()
        node = RuntimeNode(node_id="n1", tenant_scope="t1", runtime_types=["docker"])
        registry.register_node(node)

        # 1. Drain the node
        registry.drain_node("n1")
        assert node.health_status == "draining"

        # 2. New selections exclude draining nodes
        sel = await registry.select_node("docker", "t1")
        assert sel is None

        # 3. Check timeout before grace period expires (300s)
        with patch("time.time") as mock_time:
            # Drain started at t=1000
            registry._draining_nodes["n1"] = 1000.0
            mock_time.return_value = 1100.0  # 100s elapsed
            
            transitioned = await registry.check_draining_timeouts(grace_period_sec=300.0)
            assert len(transitioned) == 0
            assert node.health_status == "draining"

            # 4. Exceed grace period
            mock_time.return_value = 1301.0  # 301s elapsed
            transitioned = await registry.check_draining_timeouts(grace_period_sec=300.0)
            assert len(transitioned) == 1
            assert transitioned[0] == "n1"
            assert node.health_status == "offline"

class TestFleetMetrics:
    @pytest.mark.asyncio
    async def test_fleet_metrics_collector(self):
        registry = FleetRegistry()
        node1 = RuntimeNode(
            node_id="n1", tenant_scope="tenant-a", runtime_types=["docker"],
            total_memory=1000, total_cpu=2.0
        )
        node2 = RuntimeNode(
            node_id="n2", tenant_scope="tenant-b", runtime_types=["firecracker"],
            total_memory=2000, total_cpu=4.0
        )
        registry.register_node(node1)
        registry.register_node(node2)

        # Allocate resources on node1
        await registry.assign_execution("e1", "n1", memory=500, cpu=1.0)
        # Register a verification failure on node2
        registry.record_verification_failure("n2")

        # Expose metrics collector
        collector = FleetMetricsCollector(registry)

        # 1. Node count by state
        states = collector.get_node_counts_by_state()
        assert states["healthy"] == 2
        assert states["offline"] == 0

        # 2. Utilization
        util = collector.get_resource_utilization()
        assert util["total_memory_mb"] == 3000
        assert util["allocated_memory_mb"] == 500
        assert util["memory_utilization_percent"] == pytest.approx(16.6666, rel=1e-3)
        assert util["total_cpu_cores"] == 6.0
        assert util["allocated_cpu_cores"] == 1.0
        assert util["cpu_utilization_percent"] == pytest.approx(16.6666, rel=1e-3)

        # Breakdown by tenant
        assert util["by_tenant"]["tenant-a"]["alloc_mem"] == 500
        assert util["by_tenant"]["tenant-b"]["alloc_mem"] == 0

        # Breakdown by runtime
        assert util["by_runtime"]["docker"]["alloc_mem"] == 500
        assert util["by_runtime"]["firecracker"]["alloc_mem"] == 0

        # 3. Active Scan Count
        assert collector.get_active_scan_count() == 1

        # 4. Failure rates
        failures = collector.get_validation_failure_rate()
        assert failures["total_failures"] == 1
        assert failures["by_node"]["n2"] == 1
        assert failures["by_node"]["n1"] == 0
