import pytest
from packages.execution.fleet import (
    FleetRegistry,
    RuntimeNode,
    DefaultVersionCompatibilityPolicy
)

class TestVersionCompatibility:
    @pytest.mark.asyncio
    async def test_compatibility_policy_rules(self):
        policy = DefaultVersionCompatibilityPolicy()
        
        # 1. Major mismatch: reject
        assert await policy.allows("2.0.0", "1.0.0") is False
        assert await policy.allows("1.2.0", "2.1.0") is False

        # 2. Minor mismatch: allow only within compatibility skew (<= 1)
        assert await policy.allows("1.2.0", "1.1.0") is True
        assert await policy.allows("1.2.0", "1.3.0") is True
        assert await policy.allows("1.2.0", "1.0.0") is False
        assert await policy.allows("1.2.0", "1.4.0") is False

        # 3. Patch mismatch: allow if contract schema is unchanged
        assert await policy.allows("1.2.1", "1.2.0") is True
        assert await policy.allows("1.2.0", "1.2.5") is True

        # 4. Invalid versions
        assert await policy.allows("invalid", "1.2.0") is False

class TestFleetRegistryExtensions:
    @pytest.mark.asyncio
    async def test_node_drain_behavior(self):
        registry = FleetRegistry()
        node = RuntimeNode(node_id="n1", tenant_scope="tenant1", runtime_types=["docker"])
        registry.register_node(node)

        # Before drain, node is selected
        selected = await registry.select_node("docker", "tenant1")
        assert selected is not None
        assert selected.node_id == "n1"

        # After drain, node is excluded
        registry.drain_node("n1")
        assert (await registry.select_node("docker", "tenant1")) is None

    @pytest.mark.asyncio
    async def test_node_quarantine_transitions_and_exclusions(self):
        registry = FleetRegistry()
        node = RuntimeNode(node_id="n1", tenant_scope="tenant1", runtime_types=["docker"])
        registry.register_node(node)

        # Increment verification failures
        registry.record_verification_failure("n1")
        assert registry._nodes["n1"].health_status == "healthy"

        registry.record_verification_failure("n1")
        assert registry._nodes["n1"].health_status == "healthy"

        # 3rd failure triggers quarantine
        registry.record_verification_failure("n1")
        assert registry._nodes["n1"].health_status == "quarantined"

        # Quarantined node is excluded from scheduling
        selected = await registry.select_node("docker", "tenant1")
        assert selected is None

    @pytest.mark.asyncio
    async def test_durable_assignment_and_reassignment_safety(self):
        registry = FleetRegistry()
        # Register target nodes to satisfy capacity checks
        registry.register_node(RuntimeNode(node_id="node1"))
        registry.register_node(RuntimeNode(node_id="node2"))
        registry.register_node(RuntimeNode(node_id="node3"))
        
        # 1. Initial assignment works
        await registry.assign_execution(execution_id="exec1", node_id="node1", has_side_effects=False)
        assert registry._ownerships["exec1"] == "node1"
        assert registry._execution_status["exec1"] == "assigned"

        # 2. Duplicate assignment prevents collision
        with pytest.raises(ValueError) as exc:
            await registry.assign_execution(execution_id="exec1", node_id="node2")
        assert "already assigned" in str(exc.value)

        # 3. Reassign works before node acknowledgment/completion
        await registry.reassign_execution("exec1", "node2")
        assert registry._ownerships["exec1"] == "node2"
        assert registry._execution_status["exec1"] == "assigned"

        # 4. Cannot reassign if acknowledged
        await registry.acknowledge_execution("exec1")
        with pytest.raises(ValueError) as exc:
            await registry.reassign_execution("exec1", "node3")
        assert "already acknowledged" in str(exc.value)

        # Reset for completed test
        await registry.complete_execution("exec1")
        with pytest.raises(ValueError) as exc:
            await registry.reassign_execution("exec1", "node3")
        assert "already completed" in str(exc.value)

    @pytest.mark.asyncio
    async def test_no_reassignment_if_has_side_effects(self):
        registry = FleetRegistry()
        # Register target nodes
        registry.register_node(RuntimeNode(node_id="node1"))
        registry.register_node(RuntimeNode(node_id="node2"))

        # Assignment with side effects
        await registry.assign_execution(execution_id="exec1", node_id="node1", has_side_effects=True)

        # Reassignment forbidden even before ack/completion
        with pytest.raises(ValueError) as exc:
            await registry.reassign_execution("exec1", "node2")
        assert "has side effects" in str(exc.value)
