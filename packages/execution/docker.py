import asyncio
import logging
import time
from typing import List, Dict, Any
from .interfaces import ContainerRuntime, ExecutionResult

logger = logging.getLogger(__name__)

class DockerRuntime(ContainerRuntime):
    """
    Interim execution adapter mapping plugin execution to the Docker API.
    Not the final security boundary; serves as a transitionary step towards
    gVisor/Kata container execution.

    Each tenant gets an ephemeral bridge network (`sentinel-net-{tenant_id}`)
    created before container launch and torn down after execution completes.
    No shared network fallback — every tenant is isolated.
    """

    async def _create_tenant_network(self, network_name: str) -> bool:
        """Create an ephemeral tenant-specific bridge network. Returns True on success."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "network", "create",
                "--driver=bridge",
                "--internal",
                network_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_bytes = await proc.communicate()
            if proc.returncode != 0:
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                # Network may already exist from a prior incomplete teardown — treat as success.
                if "already exists" in stderr:
                    logger.warning(f"Tenant network {network_name} already exists, reusing.")
                    return True
                logger.error(f"Failed to create tenant network {network_name}: {stderr}")
                return False
            return True
        except FileNotFoundError:
            logger.error("Docker CLI not found — cannot create tenant network.")
            return False

    async def _remove_tenant_network(self, network_name: str) -> None:
        """Best-effort teardown of the tenant network."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "network", "rm", network_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                logger.warning(f"Non-zero exit removing tenant network {network_name} (may already be gone).")
        except Exception as exc:
            logger.warning(f"Error tearing down tenant network {network_name}: {exc}")

    async def execute(
        self,
        image: str,
        command: List[str],
        env: Dict[str, str],
        capabilities: List[str],
        tenant_id: str = "default",
    ) -> ExecutionResult:
        network_name = f"sentinel-net-{tenant_id}"

        # --- Determine network mode ---
        if "network:external" in capabilities:
            # External access requested — use default bridge (internet-reachable).
            use_network = "bridge"
            needs_tenant_network = False
        else:
            # Both 'no capabilities' and 'network:internal' route through the
            # tenant-scoped isolated bridge.  The network is created with
            # --internal so it has no outbound internet access.
            use_network = network_name
            needs_tenant_network = True

        # --- Create ephemeral tenant network if required ---
        if needs_tenant_network:
            created = await self._create_tenant_network(network_name)
            if not created:
                return ExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Failed to provision tenant network {network_name}.",
                    duration_ms=0,
                )

        docker_args = [
            "run",
            "--rm",
            "-i",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=50",
            "--memory=512m",
            "--cpus=0.5",
            f"--network={use_network}",
        ]

        if "filesystem:write" not in capabilities:
            docker_args.append("--read-only")
            if "filesystem:read" not in capabilities:
                # A true gVisor runtime would enforce no-read.
                pass
        else:
            # Mount a strictly isolated tmpfs volume for writable scratch space.
            docker_args.append("--tmpfs=/tmp:rw,noexec,nosuid,size=64m")

        for k, v in env.items():
            docker_args.extend(["-e", f"{k}={v}"])

        docker_args.append(image)
        docker_args.extend(command)

        logger.info(f"Executing DockerRuntime with image: {image}, tenant: {tenant_id}")

        start_time = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                *docker_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout_bytes, stderr_bytes = await proc.communicate()
            duration_ms = int((time.monotonic() - start_time) * 1000)

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            exit_code = proc.returncode or 0

            return ExecutionResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )
        except FileNotFoundError:
            logger.error("Docker CLI not found on host. DockerRuntime requires Docker daemon.")
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr="Docker CLI not found on host system.",
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )
        except Exception as e:
            logger.error(f"DockerRuntime execution failed: {e}")
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=int((time.monotonic() - start_time) * 1000),
            )
        finally:
            if needs_tenant_network:
                await self._remove_tenant_network(network_name)
