"""
Firecracker microVM runtime adapter.

Maps the ContainerRuntime abstraction to Firecracker's lightweight VM model.
Each plugin execution boots a dedicated microVM with a minimal kernel+rootfs,
constrained by the capability set granted through governance policy.

This module is an *implementation detail* of the execution package —
nothing Firecracker-specific may leak past the ContainerRuntime interface.
"""

import asyncio
import json
import logging
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from packages.execution.interfaces import ContainerRuntime, ExecutionResult
from packages.observability.slo import SLOMonitor, execution_startup_hist

logger = logging.getLogger(__name__)

# Default microVM resource caps — tunable per deployment
_DEFAULT_VCPU_COUNT = 1
_DEFAULT_MEM_SIZE_MIB = 128
_DEFAULT_TIMEOUT_SECONDS = 60
_DEFAULT_KERNEL_PATH = "/var/lib/firecracker/vmlinux"
_DEFAULT_ROOTFS_PATH = "/var/lib/firecracker/rootfs.ext4"
_FIRECRACKER_BIN = "firecracker"


@dataclass
class _VMConfig:
    """Resolved Firecracker VM configuration derived from capabilities."""
    vcpu_count: int = _DEFAULT_VCPU_COUNT
    mem_size_mib: int = _DEFAULT_MEM_SIZE_MIB
    rootfs_path: str = _DEFAULT_ROOTFS_PATH
    rootfs_overlay: bool = False          # true when filesystem:write granted
    network_enabled: bool = False         # true when any network cap granted
    tap_device: Optional[str] = None      # e.g. "tap0"
    network_mode: str = "none"            # "none" | "internal" | "external"
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


def _map_capabilities(capabilities: List[str]) -> _VMConfig:
    """Translate abstract capability tokens into Firecracker VM settings."""
    cfg = _VMConfig()

    for cap in capabilities:
        low = cap.strip().lower()

        # --- memory ---
        if low.startswith("memory:") and low.endswith("m"):
            try:
                cfg.mem_size_mib = int(low[len("memory:"):-1])
            except ValueError:
                logger.warning("Ignoring malformed memory capability: %s", cap)

        # --- cpu ---
        elif low.startswith("cpu:"):
            try:
                cfg.vcpu_count = int(low[len("cpu:"):])
            except ValueError:
                logger.warning("Ignoring malformed cpu capability: %s", cap)

        # --- filesystem ---
        elif low == "filesystem:write":
            cfg.rootfs_overlay = True

        # --- network ---
        elif low == "network:internal":
            cfg.network_enabled = True
            cfg.network_mode = "internal"
            cfg.tap_device = "tap0"
        elif low == "network:external":
            cfg.network_enabled = True
            cfg.network_mode = "external"
            cfg.tap_device = "tap0"

        # --- timeout ---
        elif low.startswith("timeout:"):
            try:
                cfg.timeout_seconds = int(low[len("timeout:"):])
            except ValueError:
                logger.warning("Ignoring malformed timeout capability: %s", cap)

    return cfg


def _build_vm_config_json(
    cfg: _VMConfig,
    kernel_path: str,
    image: str,
) -> dict:
    """Build the Firecracker JSON config for the microVM."""
    rootfs = image if image else cfg.rootfs_path

    config: dict = {
        "boot-source": {
            "kernel_image_path": kernel_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": rootfs,
                "is_root_device": True,
                "is_read_only": not cfg.rootfs_overlay,
            }
        ],
        "machine-config": {
            "vcpu_count": cfg.vcpu_count,
            "mem_size_mib": cfg.mem_size_mib,
        },
    }

    if cfg.network_enabled and cfg.tap_device:
        config["network-interfaces"] = [
            {
                "iface_id": "eth0",
                "guest_mac": "AA:FC:00:00:00:01",
                "host_dev_name": cfg.tap_device,
            }
        ]

    return config


def validate_benchmark_limits(cfg: _VMConfig) -> None:
    """Enforce strict memory and CPU benchmark boundaries for production workloads."""
    if not (128 <= cfg.mem_size_mib <= 1024):
        raise ValueError(f"Firecracker memory allocation of {cfg.mem_size_mib} MiB violates benchmark boundaries [128, 1024].")
    if not (1 <= cfg.vcpu_count <= 4):
        raise ValueError(f"Firecracker CPU allocation of {cfg.vcpu_count} vCPUs violates benchmark boundaries [1, 4].")


class ProductionFirecrackerPolicy:
    """
    Readiness gate check for promoting Firecracker microVMs to production.
    All 5 gates must be True for Firecracker to be considered production-eligible.
    """
    def __init__(
        self,
        jailer_enabled: bool = False,
        benchmark_validation_completed: bool = False,
        security_validation_completed: bool = False,
        operational_runbook_completed: bool = False,
        fleet_capability_explicitly_enabled: bool = False,
    ):
        self.jailer_enabled = jailer_enabled
        self.benchmark_validation_completed = benchmark_validation_completed
        self.security_validation_completed = security_validation_completed
        self.operational_runbook_completed = operational_runbook_completed
        self.fleet_capability_explicitly_enabled = fleet_capability_explicitly_enabled

    def is_eligible(self) -> bool:
        return (
            self.jailer_enabled
            and self.benchmark_validation_completed
            and self.security_validation_completed
            and self.operational_runbook_completed
            and self.fleet_capability_explicitly_enabled
        )


class FirecrackerRuntime(ContainerRuntime):
    """Execute plugins inside Firecracker microVMs.

    Each call to :meth:`execute` boots a fresh, single-use VM, runs the
    requested command inside it, and tears it down.  The microVM's resource
    envelope is derived entirely from the ``capabilities`` list provided by the
    governance layer.
    """

    def __init__(
        self,
        *,
        firecracker_bin: str = _FIRECRACKER_BIN,
        kernel_path: str = _DEFAULT_KERNEL_PATH,
        default_rootfs: str = _DEFAULT_ROOTFS_PATH,
        jailer_bin: str = "jailer",
        jailer_uid: int = 1000,
        jailer_gid: int = 1000,
        use_jailer: bool = False,
        chroot_base_dir: str = "/srv/jailer",
    ):
        self._fc_bin = firecracker_bin
        self._kernel_path = kernel_path
        self._default_rootfs = default_rootfs
        self._jailer_bin = jailer_bin
        self._jailer_uid = jailer_uid
        self._jailer_gid = jailer_gid
        self._use_jailer = use_jailer
        self._chroot_base_dir = chroot_base_dir

    async def execute(
        self,
        image: str,
        command: List[str],
        env: Dict[str, str],
        capabilities: List[str],
    ) -> ExecutionResult:
        cfg = _map_capabilities(capabilities)
        start_time = time.monotonic()

        try:
            # Enforce benchmark validation checks
            validate_benchmark_limits(cfg)
        except ValueError as e:
            logger.error(f"Benchmark limits validation failed: {e}")
            from packages.observability.metrics import firecracker_jailer_start_failures
            firecracker_jailer_start_failures.add(1, {"runtime_type": "firecracker"})
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        vm_config = _build_vm_config_json(
            cfg,
            kernel_path=self._kernel_path,
            image=image or self._default_rootfs,
        )

        # Write config to transient config file
        try:
            config_file = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                prefix="fc_cfg_",
                delete=False,
            )
            json.dump(vm_config, config_file)
            config_file.close()
        except OSError as exc:
            logger.error("Failed to write Firecracker VM config: %s", exc)
            from packages.observability.metrics import firecracker_jailer_start_failures
            firecracker_jailer_start_failures.add(1, {"runtime_type": "firecracker"})
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Config write error: {exc}",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        # Assemble CLI invocation
        if self._use_jailer:
            vm_id = f"sentinel-vm-{int(time.time())}"
            fc_args = [
                self._jailer_bin,
                "--id", vm_id,
                "--exec-file", self._fc_bin,
                "--uid", str(self._jailer_uid),
                "--gid", str(self._jailer_gid),
                "--chroot-base-dir", self._chroot_base_dir,
                "--",
                "--config-file", config_file.name,
            ]
        else:
            fc_args = self._build_cli_args(config_file.name)

        # Spawn Firecracker
        try:
            with SLOMonitor(execution_startup_hist, {"runtime": "firecracker"}):
                proc = await asyncio.create_subprocess_exec(
                    *fc_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=self._build_env(env),
                )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=cfg.timeout_seconds,
            )
            duration_ms = int((time.monotonic() - start_time) * 1000)

            return ExecutionResult(
                exit_code=proc.returncode or 0,
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace"),
                duration_ms=duration_ms,
            )

        except FileNotFoundError:
            logger.error("Firecracker/Jailer binary not found.")
            from packages.observability.metrics import firecracker_jailer_start_failures
            firecracker_jailer_start_failures.add(1, {"runtime_type": "firecracker"})
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Jailer/Firecracker binary not found.",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        except asyncio.TimeoutError:
            logger.error("Firecracker VM execution timed out")
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Execution timed out after {cfg.timeout_seconds}s",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        except Exception as exc:
            logger.error("Firecracker/Jailer execution failed: %s", exc)
            from packages.observability.metrics import firecracker_jailer_start_failures
            firecracker_jailer_start_failures.add(1, {"runtime_type": "firecracker"})
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )

        finally:
            try:
                Path(config_file.name).unlink(missing_ok=True)
            except OSError:
                pass

    def _build_cli_args(self, config_path: str) -> List[str]:
        return [
            self._fc_bin,
            "--config-file", config_path,
            "--no-api",
        ]

    @staticmethod
    def _build_env(env: Dict[str, str]) -> Dict[str, str]:
        import os
        safe_env: Dict[str, str] = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
        }
        host_path = os.environ.get("PATH", "")
        if host_path:
            safe_env["PATH"] = host_path
        safe_env.update(env)
        return safe_env
