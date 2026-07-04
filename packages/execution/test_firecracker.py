"""Tests for the Firecracker microVM runtime adapter.

Validates interface compliance, graceful error handling, and capability-to-VM
configuration mapping — all without requiring an actual Firecracker binary.
"""

import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from packages.execution.interfaces import ContainerRuntime, ExecutionResult
from packages.execution.firecracker import (
    FirecrackerRuntime,
    _map_capabilities,
    _VMConfig,
    _build_vm_config_json,
)

from contextlib import contextmanager


@contextmanager
def _noop_ctx():
    yield


def _mock_slo_ctx(*_args, **_kwargs):
    """Drop-in replacement for SLOMonitor that avoids OTel proxy issues."""
    return _noop_ctx()


# ------------------------------------------------------------------ #
# 1. Interface compliance                                             #
# ------------------------------------------------------------------ #

def test_firecracker_implements_runtime():
    """FirecrackerRuntime must be a concrete subclass of ContainerRuntime."""
    assert issubclass(FirecrackerRuntime, ContainerRuntime)
    # It should also be instantiable without error
    rt = FirecrackerRuntime()
    assert isinstance(rt, ContainerRuntime)


# ------------------------------------------------------------------ #
# 2. Missing binary → graceful error                                  #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_firecracker_missing_binary():
    """When the firecracker binary is absent, execute() must return a
    descriptive error result rather than propagating the exception."""
    rt = FirecrackerRuntime(firecracker_bin="firecracker")

    with patch("packages.execution.firecracker.SLOMonitor", _mock_slo_ctx):
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("firecracker")):
            result = await rt.execute(
                image="/tmp/rootfs.ext4",
                command=["echo", "hello"],
                env={},
                capabilities=[],
            )

    assert isinstance(result, ExecutionResult)
    assert result.exit_code == -1
    assert "not found" in result.stderr.lower()


# ------------------------------------------------------------------ #
# 3. Capability mapping                                               #
# ------------------------------------------------------------------ #

class TestCapabilityMapping:
    """Verify that abstract capabilities map to correct VM settings."""

    def test_network_external(self):
        cfg = _map_capabilities(["network:external"])
        assert cfg.network_enabled is True
        assert cfg.network_mode == "external"
        assert cfg.tap_device == "tap0"

    def test_network_internal(self):
        cfg = _map_capabilities(["network:internal"])
        assert cfg.network_enabled is True
        assert cfg.network_mode == "internal"
        assert cfg.tap_device == "tap0"

    def test_no_network_by_default(self):
        cfg = _map_capabilities([])
        assert cfg.network_enabled is False
        assert cfg.network_mode == "none"
        assert cfg.tap_device is None

    def test_filesystem_write_enables_overlay(self):
        cfg = _map_capabilities(["filesystem:write"])
        assert cfg.rootfs_overlay is True

    def test_filesystem_read_only_by_default(self):
        cfg = _map_capabilities([])
        assert cfg.rootfs_overlay is False

    def test_memory_cap(self):
        cfg = _map_capabilities(["memory:256m"])
        assert cfg.mem_size_mib == 256

    def test_cpu_cap(self):
        cfg = _map_capabilities(["cpu:2"])
        assert cfg.vcpu_count == 2

    def test_timeout_cap(self):
        cfg = _map_capabilities(["timeout:30"])
        assert cfg.timeout_seconds == 30

    def test_malformed_cap_ignored(self):
        """Malformed capabilities must not crash; defaults should remain."""
        cfg = _map_capabilities(["memory:xyz", "cpu:abc", "timeout:nope"])
        assert cfg.mem_size_mib == 128   # default
        assert cfg.vcpu_count == 1       # default
        assert cfg.timeout_seconds == 60  # default

    def test_combined_capabilities(self):
        cfg = _map_capabilities([
            "memory:512m",
            "cpu:4",
            "filesystem:write",
            "network:external",
            "timeout:120",
        ])
        assert cfg.mem_size_mib == 512
        assert cfg.vcpu_count == 4
        assert cfg.rootfs_overlay is True
        assert cfg.network_enabled is True
        assert cfg.network_mode == "external"
        assert cfg.timeout_seconds == 120


# ------------------------------------------------------------------ #
# 4. VM config JSON generation                                       #
# ------------------------------------------------------------------ #

class TestVMConfigJSON:
    """The JSON config passed to Firecracker must reflect capabilities."""

    def test_read_only_rootfs(self):
        cfg = _VMConfig(rootfs_overlay=False)
        config = _build_vm_config_json(cfg, "/boot/vmlinux", "/rootfs.ext4")
        drive = config["drives"][0]
        assert drive["is_read_only"] is True

    def test_writable_rootfs_overlay(self):
        cfg = _VMConfig(rootfs_overlay=True)
        config = _build_vm_config_json(cfg, "/boot/vmlinux", "/rootfs.ext4")
        drive = config["drives"][0]
        assert drive["is_read_only"] is False

    def test_network_interface_present(self):
        cfg = _VMConfig(network_enabled=True, tap_device="tap0")
        config = _build_vm_config_json(cfg, "/boot/vmlinux", "/rootfs.ext4")
        assert "network-interfaces" in config
        assert config["network-interfaces"][0]["host_dev_name"] == "tap0"

    def test_no_network_interface_when_disabled(self):
        cfg = _VMConfig(network_enabled=False)
        config = _build_vm_config_json(cfg, "/boot/vmlinux", "/rootfs.ext4")
        assert "network-interfaces" not in config

    def test_machine_config(self):
        cfg = _VMConfig(vcpu_count=4, mem_size_mib=1024)
        config = _build_vm_config_json(cfg, "/boot/vmlinux", "/rootfs.ext4")
        mc = config["machine-config"]
        assert mc["vcpu_count"] == 4
        assert mc["mem_size_mib"] == 1024


# ------------------------------------------------------------------ #
# 5. Successful execution path                                       #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_firecracker_successful_execution():
    """Happy-path: subprocess returns exit 0 with stdout/stderr."""
    rt = FirecrackerRuntime()

    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(return_value=(b"output\n", b""))
    mock_proc.returncode = 0

    with patch("packages.execution.firecracker.SLOMonitor", _mock_slo_ctx):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await rt.execute(
                image="/tmp/rootfs.ext4",
                command=["echo", "test"],
                env={"FOO": "bar"},
                capabilities=["memory:256m", "cpu:2"],
            )

    assert result.exit_code == 0
    assert "output" in result.stdout
    assert result.duration_ms >= 0


# ------------------------------------------------------------------ #
# 6. Timeout handling                                                 #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_firecracker_timeout():
    """When the VM exceeds its timeout, execute() must return an error
    result and attempt to kill the process."""
    rt = FirecrackerRuntime()

    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_proc.kill = MagicMock()

    with patch("packages.execution.firecracker.SLOMonitor", _mock_slo_ctx):
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            # asyncio.wait_for wraps communicate; patch it to raise TimeoutError
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                result = await rt.execute(
                    image="/tmp/rootfs.ext4",
                    command=["long_running"],
                    env={},
                    capabilities=["timeout:5"],
                )

    assert result.exit_code == -1
    assert "timed out" in result.stderr.lower()


# ------------------------------------------------------------------ #
# 7. SLO metric integration                                          #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_firecracker_records_slo_metric():
    """Verify that the SLO startup histogram is exercised during execute()."""
    rt = FirecrackerRuntime()

    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(return_value=(b"", b""))
    mock_proc.returncode = 0

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("packages.execution.firecracker.SLOMonitor") as mock_slo:
            mock_ctx = MagicMock()
            mock_slo.return_value.__enter__ = MagicMock(return_value=mock_ctx)
            mock_slo.return_value.__exit__ = MagicMock(return_value=False)
            await rt.execute("/rootfs.ext4", ["echo"], {}, [])

            mock_slo.assert_called_once()
            args, kwargs = mock_slo.call_args
            assert kwargs.get("runtime") == "firecracker" or \
                   (len(args) > 1 and args[1].get("runtime") == "firecracker") or \
                   (len(args) == 2 and args[1] == {"runtime": "firecracker"})
