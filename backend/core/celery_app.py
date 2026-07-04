import os
import logging
import json
import threading
import subprocess
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Try importing celery. If not installed, we provide a robust mock for fallback execution
try:
    from celery import Celery
    import redis
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

if CELERY_AVAILABLE:
    celery_app = Celery("sentinel", broker=redis_url, backend=redis_url)
    celery_app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
    )
    redis_client = redis.from_url(redis_url)
else:
    celery_app = None
    redis_client = None
    logger.warning("Celery packages not found in requirements. Expected for API node, but required for Worker node.")

def run_distributed_scan(job_id: str, command: str, tool_name: str) -> Dict[str, Any]:
    """Worker task implementation to run scanner subprocesses on distributed nodes and stream output to Redis."""
    logger.info(f"Worker executing task {job_id} [{tool_name}]: {command}")
    
    import asyncio
    from packages.plugin_sdk.manifest import plugin_loader

    plugin_scanner = plugin_loader.get_scanner(tool_name)
    if not plugin_scanner:
        err_msg = f"Execution blocked: tool '{tool_name}' is not registered as a plugin in the Execution Context."
        logger.error(err_msg)
        if redis_client:
            redis_client.publish("sentinel_telemetry", json.dumps({
                "type": "terminal_output", "job_id": job_id, "stream": "stderr", "line": err_msg, "tool": tool_name
            }))
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": err_msg,
        }

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    try:
        if redis_client:
            redis_client.publish("sentinel_telemetry", json.dumps({
                "type": "terminal_output", "job_id": job_id, "stream": "stdout", "line": f"[SENTINEL] Sandboxed execution started for {tool_name}...", "tool": tool_name
            }))
            
        execution_result = loop.run_until_complete(plugin_scanner.execute(command))
        
        if redis_client:
            # Stream final logs back to redis
            for line in execution_result.stdout.splitlines():
                redis_client.publish("sentinel_telemetry", json.dumps({
                    "type": "terminal_output", "job_id": job_id, "stream": "stdout", "line": line, "tool": tool_name
                }))
            for line in execution_result.stderr.splitlines():
                redis_client.publish("sentinel_telemetry", json.dumps({
                    "type": "terminal_output", "job_id": job_id, "stream": "stderr", "line": line, "tool": tool_name
                }))

        return {
            "exit_code": execution_result.exit_code,
            "stdout": execution_result.stdout,
            "stderr": execution_result.stderr,
        }
    except Exception as e:
        logger.error(f"Sandboxed distributed execution failed for job {job_id}: {e}")
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
        }

if CELERY_AVAILABLE and celery_app:
    @celery_app.task(name="sentinel.run_distributed_scan")
    def run_distributed_scan_task(job_id: str, command: str, tool_name: str) -> Dict[str, Any]:
        return run_distributed_scan(job_id, command, tool_name)
else:
    def run_distributed_scan_task(*args, **kwargs):
        raise NotImplementedError("Celery is not available. Run under fallback local queue.")
