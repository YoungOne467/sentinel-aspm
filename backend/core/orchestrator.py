"""
Task Orchestrator — async CLI execution wrapper with psutil memory guardrails.
Streams stdout/stderr in real-time via WebSocket broadcast.
Dynamically throttles concurrency when available RAM drops below threshold.
"""
import asyncio
import logging
import sys
import zlib
import subprocess
import threading
from datetime import datetime, timezone
from typing import Callable, Optional, Dict, Any, List

import psutil
from sqlalchemy import update

from core.database import AsyncSessionLocal
from core.models import Job, gen_id
from core.celery_app import CELERY_AVAILABLE, run_distributed_scan_task, run_distributed_scan
from packages.plugin_sdk.manifest import plugin_loader

logger = logging.getLogger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_MAX_CONCURRENT = 4
MEMORY_FLOOR_MB = 1536  # 1.5 GB — throttle below this
MEMORY_CHECK_INTERVAL = 5  # seconds between RAM checks
STDOUT_COMPRESS_THRESHOLD = 50_000  # characters — compress if larger


class TaskOrchestrator:
    """Manages async execution of CLI tools with resource-aware throttling."""

    def __init__(self, max_concurrent: int = DEFAULT_MAX_CONCURRENT):
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_jobs: Dict[str, asyncio.subprocess.Process] = {}
        self._broadcast: Optional[Callable] = None
        self._throttled = False

    def set_broadcast(self, broadcast_fn: Callable):
        self._broadcast = broadcast_fn

    # ─── Public API ────────────────────────────────────────────────────────

    async def execute_job(self, job_id: str, command: str, tool_name: str) -> Dict[str, Any]:
        """Execute a scanner task asynchronously via distributed broker (Celery) or local queue fallback."""
        # Resolve dynamic settings from database
        max_workers = DEFAULT_MAX_CONCURRENT
        try:
            from core.database import AsyncSessionLocal
            from core.models import PlatformSettings
            async with AsyncSessionLocal() as session:
                settings = await session.get(PlatformSettings, "default")
                if settings and settings.max_concurrent_workers:
                    max_workers = settings.max_concurrent_workers
        except Exception:
            pass

        # Update semaphore if max_workers changed
        if max_workers != self._max_concurrent:
            self._max_concurrent = max_workers
            self._semaphore = asyncio.Semaphore(max_workers)

        # Wait for memory headroom before acquiring semaphore
        await self._wait_for_memory()
        async with self._semaphore:
            await self._update_job_status(job_id, "running", started_at=datetime.now(timezone.utc))

            await self._broadcast_msg({
                "type": "job_status", "job_id": job_id,
                "status": "running", "tool": tool_name,
            })

            # Check if pluggable YAML/JSON scanner matches the requested tool
            plugin_scanner = plugin_loader.get_scanner(tool_name)

            try:
                if plugin_scanner:
                    logger.info(f"Using pluggable scanner engine {tool_name} for target: {command}")
                    exec_res = await plugin_scanner.execute(command)
                    result = {
                        "exit_code": exec_res.exit_code,
                        "stdout": exec_res.stdout,
                        "stderr": exec_res.stderr
                    }
                # Distributed architecture dispatch
                else:
                    logger.info(f"Pushing job {job_id} to message broker.")
                    try:
                        task = run_distributed_scan_task.delay(job_id, command, tool_name)
                        # Non-blocking async loop waiting for Celery response
                        while not task.ready():
                            await asyncio.sleep(0.5)
                        result = task.result
                    except Exception as celery_err:
                        logger.warning(
                            "Celery broker/backend communication failed: %s. Falling back to local execution loop.",
                            celery_err
                        )
                        # Fallback to local subprocess execution if redis/celery is unavailable
                        proc = await asyncio.create_subprocess_shell(
                            command,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        self._active_jobs[job_id] = proc
                        stdout_data, stderr_data = await proc.communicate()
                        result = {
                            "exit_code": proc.returncode,
                            "stdout": stdout_data.decode(errors="replace"),
                            "stderr": stderr_data.decode(errors="replace")
                        }

                exit_code = result.get("exit_code", 0)
                raw_stdout = result.get("stdout", "")
                raw_stderr = result.get("stderr", "")

                # Storage hygiene: compress large outputs
                full_stdout = raw_stdout
                compressed = False
                if len(full_stdout) > STDOUT_COMPRESS_THRESHOLD:
                    full_stdout = zlib.compress(full_stdout.encode()).hex()
                    compressed = True

                status = "completed" if exit_code == 0 else "failed"
                await self._update_job_status(
                    job_id, status,
                    exit_code=exit_code,
                    stdout=full_stdout,
                    stderr=raw_stderr,
                    stdout_compressed=compressed,
                    completed_at=datetime.now(timezone.utc),
                )
                
                # If using declarative plugins, parse custom rules findings dynamically
                if plugin_scanner:
                    parsed_findings = plugin_scanner.parse_output(raw_stdout, raw_stderr)
                    if parsed_findings:
                        logger.info(f"Declarative plugin parsed {len(parsed_findings)} custom findings.")
                        async with AsyncSessionLocal() as session:
                            from core.models import Finding
                            for f in parsed_findings:
                                new_find = Finding(
                                    id=gen_id("f"),
                                    job_id=job_id,
                                    target_id="t-1",  # Associated workstation target scope
                                    title=f["title"],
                                    severity=f["severity"],
                                    category=f["category"],
                                    description=f["description"],
                                    evidence=f["evidence"],
                                    solution=f["solution"],
                                    status="open"
                                )
                                session.add(new_find)
                            await session.commit()

                await self._broadcast_msg({
                    "type": "job_status", "job_id": job_id,
                    "status": status, "exit_code": exit_code, "tool": tool_name,
                })
                return {"job_id": job_id, "status": status, "exit_code": exit_code, "stdout": raw_stdout, "stderr": raw_stderr}

            except Exception as e:
                logger.error("Job %s execution error: %s: %s", job_id, type(e).__name__, e, exc_info=True)
                await self._update_job_status(
                    job_id, "failed",
                    stderr=f"{type(e).__name__}: {e}",
                    completed_at=datetime.now(timezone.utc),
                )
                await self._broadcast_msg({
                    "type": "job_status", "job_id": job_id,
                    "status": "failed", "error": f"{type(e).__name__}: {e}",
                })
                return {"job_id": job_id, "status": "failed", "exit_code": None, "error": repr(e), "stdout": "", "stderr": repr(e)}
            finally:
                self._active_jobs.pop(job_id, None)

    async def cancel_job(self, job_id: str) -> bool:
        proc = self._active_jobs.get(job_id)
        if proc:
            kill_process_tree(proc)
            await self._update_job_status(
                job_id, "cancelled",
                completed_at=datetime.now(timezone.utc),
            )
            return True
        return False

    def get_active_jobs(self) -> List[str]:
        return list(self._active_jobs.keys())

    def get_system_stats(self) -> Dict[str, Any]:
        mem = psutil.virtual_memory()
        return {
            "cpu_percent": psutil.cpu_percent(interval=0),
            "memory_total_mb": round(mem.total / 1024 / 1024),
            "memory_available_mb": round(mem.available / 1024 / 1024),
            "memory_percent": mem.percent,
            "active_jobs": len(self._active_jobs),
            "max_concurrent": self._max_concurrent,
            "throttled": self._throttled,
        }

    # ─── Internal ──────────────────────────────────────────────────────────

    async def _wait_for_memory(self):
        """Block if available memory is below the safety floor."""
        while True:
            available_mb = psutil.virtual_memory().available / 1024 / 1024
            if available_mb >= MEMORY_FLOOR_MB:
                if self._throttled:
                    self._throttled = False
                    logger.info("Memory recovered to %.0f MB — resuming job queue", available_mb)
                break
            if not self._throttled:
                self._throttled = True
                logger.warning(
                    "Available memory %.0f MB < %d MB floor — throttling job queue",
                    available_mb, MEMORY_FLOOR_MB,
                )
                await self._broadcast_msg({
                    "type": "system_alert",
                    "level": "warning",
                    "message": f"Low memory ({available_mb:.0f} MB). Job queue throttled.",
                })
            await asyncio.sleep(MEMORY_CHECK_INTERVAL)

    async def _broadcast_msg(self, msg: dict):
        if self._broadcast:
            try:
                await self._broadcast(msg)
            except Exception as e:
                logger.error("Broadcast error: %s", e)

    async def _update_job_status(self, job_id: str, status: str, **kwargs):
        try:
            from datetime import datetime
            async with AsyncSessionLocal() as session:
                values = {"status": status}
                for k, v in kwargs.items():
                    if isinstance(v, datetime):
                        values[k] = v.replace(tzinfo=None)
                    else:
                        values[k] = v
                await session.execute(
                    update(Job).where(Job.id == job_id).values(**values)
                )
                await session.commit()
        except Exception as e:
            logger.error("Failed to update job %s status: %s", job_id, e)


# Global singleton
orchestrator = TaskOrchestrator(max_concurrent=DEFAULT_MAX_CONCURRENT)
