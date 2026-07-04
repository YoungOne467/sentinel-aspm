import pytest
from unittest.mock import patch, MagicMock, AsyncMock, call

from packages.execution.docker import DockerRuntime
from packages.execution.fleet import FleetRegistry, RuntimeNode


def _make_mock_proc(stdout=b"", stderr=b"", returncode=0):
    """Helper: build a mock process returned by create_subprocess_exec."""
    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(return_value=(stdout, stderr))
    mock_proc.returncode = returncode
    return mock_proc


@pytest.mark.asyncio
async def test_docker_filesystem():
    runtime = DockerRuntime()
    # Mock subprocess to avoid requiring local docker daemon in tests
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        # Three subprocess calls: network create → docker run → network rm
        mock_exec.return_value = _make_mock_proc(stdout=b"{}")

        # Authorize filesystem:write -> tmpfs should be added
        res = await runtime.execute("alpine", ["echo", "test"], {}, ["filesystem:write"])
        assert res.exit_code == 0
        # The docker run call is the second invocation (after network create)
        run_call_args = mock_exec.call_args_list[1][0]
        assert "--tmpfs=/tmp:rw,noexec,nosuid,size=64m" in run_call_args


@pytest.mark.asyncio
async def test_fleet_registration_and_scheduling():
    registry = FleetRegistry(stale_timeout_sec=1.0)

    node = RuntimeNode(node_id="node-1", tenant_scope="default", runtime_types=["docker"])
    registry.register_node(node)

    healthy = await registry.get_healthy_nodes("default")
    assert len(healthy) == 1
    assert healthy[0].node_id == "node-1"

    selected = await registry.select_node(required_runtime="docker", tenant_id="default")
    assert selected is not None
    assert selected.node_id == "node-1"


@pytest.mark.asyncio
async def test_docker_networking_isolation():
    """No network capabilities → tenant-scoped isolated bridge network."""
    runtime = DockerRuntime()
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.return_value = _make_mock_proc()

        await runtime.execute("alpine", ["echo", "test"], {}, [])

        # docker run call (second) should reference the tenant network, not --network=none
        run_call_args = mock_exec.call_args_list[1][0]
        assert "--network=sentinel-net-default" in run_call_args
        # Old --network=none must NOT appear
        assert "--network=none" not in run_call_args


@pytest.mark.asyncio
async def test_docker_tenant_network_creation():
    """Verify ephemeral tenant network lifecycle: create → run → rm."""
    runtime = DockerRuntime()
    tenant = "acme-corp"

    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.return_value = _make_mock_proc()

        result = await runtime.execute(
            "alpine", ["echo", "hello"], {}, [], tenant_id=tenant
        )
        assert result.exit_code == 0

        calls = mock_exec.call_args_list
        # Expect exactly 3 subprocess calls: network create, docker run, network rm.
        assert len(calls) == 3

        # --- 1. Network create ---
        net_create_args = calls[0][0]
        assert net_create_args[0] == "docker"
        assert "network" in net_create_args
        assert "create" in net_create_args
        assert f"sentinel-net-{tenant}" in net_create_args
        # Must be --internal (no internet)
        assert "--internal" in net_create_args

        # --- 2. Docker run ---
        run_args = calls[1][0]
        assert run_args[0] == "docker"
        assert "run" in run_args
        assert f"--network=sentinel-net-{tenant}" in run_args

        # --- 3. Network rm ---
        net_rm_args = calls[2][0]
        assert net_rm_args[0] == "docker"
        assert "network" in net_rm_args
        assert "rm" in net_rm_args
        assert f"sentinel-net-{tenant}" in net_rm_args


@pytest.mark.asyncio
async def test_docker_network_external_uses_bridge():
    """network:external capability should use the default 'bridge' network,
    and should NOT create/tear-down a tenant network."""
    runtime = DockerRuntime()

    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.return_value = _make_mock_proc()

        result = await runtime.execute(
            "alpine", ["nmap", "-sV", "target"], {}, ["network:external"], tenant_id="ext-tenant"
        )
        assert result.exit_code == 0

        calls = mock_exec.call_args_list
        # Only the docker run call — no network create/rm.
        assert len(calls) == 1

        run_args = calls[0][0]
        assert "--network=bridge" in run_args


@pytest.mark.asyncio
async def test_docker_network_internal_uses_tenant_network():
    """network:internal should route through the tenant-scoped internal bridge."""
    runtime = DockerRuntime()
    tenant = "internal-only"

    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_exec.return_value = _make_mock_proc()

        result = await runtime.execute(
            "alpine", ["curl", "peer"], {}, ["network:internal"], tenant_id=tenant
        )
        assert result.exit_code == 0

        # 3 calls: create, run, rm
        calls = mock_exec.call_args_list
        assert len(calls) == 3

        run_args = calls[1][0]
        assert f"--network=sentinel-net-{tenant}" in run_args
