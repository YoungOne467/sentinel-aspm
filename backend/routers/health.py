from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from typing import Any, Dict, Optional
from pathlib import Path

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from core.orchestrator import orchestrator
from core import resource_governor
from core.feed_sync import feed_sync
from core.ai_triage import ai_triage
from core.schemas import OASTSettingsUpdate
from services.scanner import (
    get_oast_settings_service,
    update_oast_settings_service,
    request_hibernation_service
)

logger = logging.getLogger("sentinel.routers.health")
router = APIRouter()

# References populated via init
_ws_manager = None
_hibernate_signal_file = None
_reconfigure_oob_poller_fn = None

def init_health_router(ws_manager, hibernate_signal_file: Path, reconfigure_oob_poller_fn):
    global _ws_manager, _hibernate_signal_file, _reconfigure_oob_poller_fn
    _ws_manager = ws_manager
    _hibernate_signal_file = hibernate_signal_file
    _reconfigure_oob_poller_fn = reconfigure_oob_poller_fn

@router.get("/api/health")
async def health():
    sys_stats = orchestrator.get_system_stats()
    ws_count = _ws_manager.count if _ws_manager else 0
    return {
        "status": "online",
        "version": "2.0.0",
        "active_jobs": sys_stats["active_jobs"],
        "ws_connections": ws_count,
        "system": sys_stats,
        "resource_governor": resource_governor.get_status(),
        "feed_sync": feed_sync.status,
        "ai_triage": ai_triage.config,
    }

@router.get("/api/system/resources")
async def system_resources():
    return resource_governor.get_status()

@router.get("/api/settings/oast")
async def get_oast_settings_endpoint():
    return await get_oast_settings_service()

@router.post("/api/settings/oast")
async def update_oast_settings_endpoint(payload: OASTSettingsUpdate):
    settings = await update_oast_settings_service(payload)
    main_module = sys.modules.get("main")
    reconfig_fn = getattr(main_module, "reconfigure_oob_poller", _reconfigure_oob_poller_fn)
    if reconfig_fn:
        await reconfig_fn()
    return settings

@router.post("/api/shutdown")
async def shutdown(background_tasks: BackgroundTasks):
    logger.info("Shutdown requested. Initiating graceful shutdown...")

    def kill_process():
        import time
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGINT)

    background_tasks.add_task(kill_process)
    return {"status": "shutting_down", "message": "Graceful shutdown initiated."}

@router.post("/api/system/hibernate", status_code=202)
async def request_hibernation():
    main_module = sys.modules.get("main")
    sig_file = getattr(main_module, "HIBERNATE_SIGNAL_FILE", _hibernate_signal_file)
    if sig_file is None:
        raise HTTPException(status_code=500, detail="Hibernate signal file path not configured")
    return await request_hibernation_service(sig_file)
