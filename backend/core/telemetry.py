import asyncio
import logging
import psutil
from typing import Optional

logger = logging.getLogger(__name__)

_telemetry_task: Optional[asyncio.Task] = None
_broadcast_fn = None

def set_broadcast(fn):
    global _broadcast_fn
    _broadcast_fn = fn

async def _broadcast(msg: dict):
    if _broadcast_fn:
        try:
            await _broadcast_fn(msg)
        except Exception as exc:
            logger.debug("Telemetry broadcast error: %s", exc)

async def telemetry_loop():
    logger.info("Telemetry loop started.")
    try:
        while True:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            ram_mb = int(mem.used / (1024 * 1024))
            tasks_count = len(asyncio.all_tasks())

            payload = {
                "type": "system_telemetry",
                "cpu": cpu,
                "ram": ram_mb,
                "tasks": tasks_count
            }

            await _broadcast(payload)
            await asyncio.sleep(2)
    except asyncio.CancelledError:
        logger.info("Telemetry loop stopped.")
        raise

async def start_telemetry():
    global _telemetry_task
    if _telemetry_task is not None and not _telemetry_task.done():
        return
    _telemetry_task = asyncio.create_task(telemetry_loop())

async def stop_telemetry():
    global _telemetry_task
    if _telemetry_task is not None:
        _telemetry_task.cancel()
        try:
            await _telemetry_task
        except asyncio.CancelledError:
            pass
        _telemetry_task = None
