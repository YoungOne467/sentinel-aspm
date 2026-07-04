"""
Resource Governor — global hardware health monitor for SENTINEL.

Polls CPU and memory utilization every 2 seconds and exposes an asyncio.Event
(``system_healthy``) that consuming coroutines can ``await`` before performing
work.  When the host exceeds the configured thresholds the event is *cleared*,
causing all waiters to block until utilization recovers.

Thresholds (configurable via env vars):
  RAM_THROTTLE_PERCENT  — pause above this   (default 85)
  CPU_THROTTLE_PERCENT  — pause above this   (default 90)
  RAM_RESUME_PERCENT    — resume below this  (default 75)
  CPU_RESUME_PERCENT    — resume below this  (default 75)
"""

import asyncio
import logging
import os
from typing import Optional

import psutil

logger = logging.getLogger(__name__)

# ─── Thresholds ────────────────────────────────────────────────────────────────
RAM_THROTTLE_PERCENT = float(os.getenv("RAM_THROTTLE_PERCENT", "85"))
CPU_THROTTLE_PERCENT = float(os.getenv("CPU_THROTTLE_PERCENT", "90"))
RAM_RESUME_PERCENT = float(os.getenv("RAM_RESUME_PERCENT", "75"))
CPU_RESUME_PERCENT = float(os.getenv("CPU_RESUME_PERCENT", "75"))
POLL_INTERVAL_SECONDS = float(os.getenv("RESOURCE_POLL_INTERVAL", "2"))

# ─── Global Event ──────────────────────────────────────────────────────────────
# Starts *set* (healthy) so nothing blocks before the monitor is started.
system_healthy: asyncio.Event = asyncio.Event()
system_healthy.set()

# ─── Internal State ────────────────────────────────────────────────────────────
_monitor_task: Optional[asyncio.Task] = None
_throttled: bool = False
_broadcast_fn = None  # optional WebSocket broadcaster


def set_broadcast(fn):
    """Register an async broadcast callback for system alerts."""
    global _broadcast_fn
    _broadcast_fn = fn


async def _broadcast(msg: dict):
    if _broadcast_fn:
        try:
            await _broadcast_fn(msg)
        except Exception as exc:
            logger.debug("Resource governor broadcast error: %s", exc)


# ─── Monitor Coroutine ────────────────────────────────────────────────────────

async def monitor_system_health():
    """
    Background task that polls host CPU and RAM every ``POLL_INTERVAL_SECONDS``
    and toggles ``system_healthy`` accordingly.
    """
    global _throttled

    logger.info(
        "Resource governor started — RAM ↑%s%% ↓%s%% · CPU ↑%s%% ↓%s%% · poll %ss",
        RAM_THROTTLE_PERCENT, RAM_RESUME_PERCENT,
        CPU_THROTTLE_PERCENT, CPU_RESUME_PERCENT,
        POLL_INTERVAL_SECONDS,
    )

    # Prime the CPU measurement (first call always returns 0.0)
    psutil.cpu_percent(interval=None)

    try:
        while True:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

            mem = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=None)
            ram_pct = mem.percent

            if not _throttled:
                # Check if we need to THROTTLE
                if ram_pct >= RAM_THROTTLE_PERCENT or cpu >= CPU_THROTTLE_PERCENT:
                    _throttled = True
                    system_healthy.clear()
                    logger.warning(
                        "Hardware threshold exceeded (RAM %.1f%% / CPU %.1f%%). "
                        "Throttling queues.",
                        ram_pct, cpu,
                    )
                    await _broadcast({
                        "type": "system_alert",
                        "level": "warning",
                        "message": (
                            f"Resource governor: throttling — "
                            f"RAM {ram_pct:.1f}% / CPU {cpu:.1f}%"
                        ),
                    })
            else:
                # Check if we can RESUME
                if ram_pct < RAM_RESUME_PERCENT and cpu < CPU_RESUME_PERCENT:
                    _throttled = False
                    system_healthy.set()
                    logger.info(
                        "Resource utilization recovered (RAM %.1f%% / CPU %.1f%%). "
                        "Resuming queues.",
                        ram_pct, cpu,
                    )
                    await _broadcast({
                        "type": "system_alert",
                        "level": "info",
                        "message": (
                            f"Resource governor: resumed — "
                            f"RAM {ram_pct:.1f}% / CPU {cpu:.1f}%"
                        ),
                    })
    except asyncio.CancelledError:
        logger.info("Resource governor monitor stopped.")
        raise


# ─── Lifecycle Helpers ─────────────────────────────────────────────────────────

async def start_monitor():
    """Launch the monitor as a background task. Safe to call multiple times."""
    global _monitor_task
    if _monitor_task is not None and not _monitor_task.done():
        return  # already running
    _monitor_task = asyncio.create_task(monitor_system_health())
    logger.info("Resource governor background task created.")


async def stop_monitor():
    """Cancel the monitor task gracefully."""
    global _monitor_task, _throttled
    if _monitor_task is not None:
        _monitor_task.cancel()
        try:
            await _monitor_task
        except asyncio.CancelledError:
            pass
        _monitor_task = None
    # Always leave the event set so nothing hangs after shutdown
    _throttled = False
    system_healthy.set()
    logger.info("Resource governor stopped and event reset.")


def get_status() -> dict:
    """Return a snapshot of the governor's current state."""
    mem = psutil.virtual_memory()
    return {
        "throttled": _throttled,
        "ram_percent": mem.percent,
        "ram_available_mb": round(mem.available / 1024 / 1024),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "thresholds": {
            "ram_throttle": RAM_THROTTLE_PERCENT,
            "cpu_throttle": CPU_THROTTLE_PERCENT,
            "ram_resume": RAM_RESUME_PERCENT,
            "cpu_resume": CPU_RESUME_PERCENT,
        },
    }
