import sys
import os
from pathlib import Path

# Add project root and backend folder to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

import platform
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from tasks.mitre_sync import sync_mitre
from core.database import AsyncSessionLocal
platform._wmi = None

import sys
import asyncio
import traceback

# Force Windows to use the Proactor Event Loop for subprocess support
if sys.platform == 'win32':
    # Only set event loop policy on older Python versions; newer versions default to Proactor Event Loop
    if sys.version_info < (3, 8):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


import logging
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Literal, Any
from contextlib import asynccontextmanager

import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Response, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, field_validator

from core.database import AsyncSessionLocal, init_db, engine
from core.models import gen_id
from core.orchestrator import orchestrator
from core.scope_manager import scope_manager
from core.feed_sync import feed_sync
from core.ai_triage import ai_triage
from core.oob_tracker import OOBPoller
from core.oast_listener import get_oast_settings, reload_oast_settings, update_oast_settings
from core import resource_governor

from services.scanner import (
    list_targets_service, create_target_service, get_target_service,
    update_target_service, delete_target_service, get_topology_service,
    get_target_routes_service, get_target_ai_triage_service,
    get_target_logic_map_service, list_dlp_findings_service,
    list_discovered_parameters_service, list_jobs_service,
    create_job_service, get_job_service, list_findings_service,
    update_finding_service, get_findings_stats_service,
    ingest_data_service, export_data_service, list_scope_rules_service,
    create_scope_rule_service, delete_scope_rule_service,
    analyze_js_service, list_js_findings_service,
    fingerprint_host_endpoint_service, get_clusters_service,
    trigger_fuzz_service, ai_triage_endpoint_service,
    ai_poc_endpoint_service, ai_status_service,
    run_exploit_test_service, run_exploit_operator_action_service,
    stop_exploit_service, get_oast_settings_service,
    update_oast_settings_service, request_hibernation_service,
    clean_host_and_port, global_state
)

# Test-expected main exports/aliases
from core.http_client import _get_global_request_headers
from core.schemas import ScanRequest

def normalize_exploit_action(action: str) -> str:
    cleaned = str(action).strip().lower()
    if "proof" in cleaned:
        return "aggressive proof of access"
    if "access" in cleaned:
        return "access mode"
    if "deep" in cleaned:
        return "deep exfiltration"
    return cleaned

_exploit_result = None
_active_exploiter = None

# ─── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-24s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel")

# ─── Tool Registry Loader ─────────────────────────────────────────────────────

TOOL_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "core", "tool_registry.yaml")
HIBERNATE_SIGNAL_FILE = Path(__file__).resolve().parents[1] / "scratch" / "hibernate.sig"
_oob_poller: OOBPoller | None = None
_oob_poller_task: asyncio.Task | None = None


def load_tool_registry() -> dict:
    try:
        with open(TOOL_REGISTRY_PATH, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Could not load tool registry: %s", e)
        return {"tools": {}, "settings": {}}


# ─── WebSocket Manager ────────────────────────────────────────────────────────
from core.ws_manager import manager


async def start_oob_poller_if_configured() -> None:
    # Disable global background polling task for APEX Engine memory-gated execution
    return


async def stop_oob_poller() -> None:
    global _oob_poller, _oob_poller_task
    if _oob_poller:
        await _oob_poller.stop()
    if _oob_poller_task:
        _oob_poller_task.cancel()
        try:
            await _oob_poller_task
        except asyncio.CancelledError:
            pass
    _oob_poller = None
    _oob_poller_task = None


async def reconfigure_oob_poller() -> None:
    await stop_oob_poller()
    reload_oast_settings()
    await start_oob_poller_if_configured()

# ─── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Lifespan starting. Current loop policy: %s", asyncio.get_event_loop_policy())
    logger.info("Current running loop: %s", asyncio.get_running_loop())
    init_db()
    logger.info("Database initialized.")
    # Initialize APScheduler
    async def _sync_mitre_job():
        async with AsyncSessionLocal() as session:
            await sync_mitre(session)

    scheduler = AsyncIOScheduler()
    scheduler.add_job(_sync_mitre_job, 'cron', hour=2, minute=0, misfire_grace_time=3600)
    scheduler.start()
    logger.info("MITRE sync scheduled nightly at 02:00 UTC.")

    orchestrator.set_broadcast(manager.broadcast)
    asyncio.create_task(manager.listen_to_redis())
    await scope_manager.load_rules()

    # Start the global resource governor
    resource_governor.set_broadcast(manager.broadcast)
    await resource_governor.start_monitor()

    # Start feed sync in background (non-blocking)
    asyncio.create_task(feed_sync.start())

    # Start system telemetry monitoring
    from core import telemetry
    telemetry.set_broadcast(manager.broadcast)
    await telemetry.start_telemetry()

    logger.info("SENTINEL API ready.")
    yield

    # Shutdown
    from core import telemetry
    await telemetry.stop_telemetry()
    await resource_governor.stop_monitor()
    await feed_sync.stop()

    # Cancel active cognitive engine background tasks
    current_tasks = asyncio.all_tasks()
    cognitive_tasks = [t for t in current_tasks if t.get_name().startswith("cognitive_engine_")]
    if cognitive_tasks:
        logger.info("Cancelling %d active cognitive engine tasks on shutdown...", len(cognitive_tasks))
        for t in cognitive_tasks:
            t.cancel()
        await asyncio.gather(*cognitive_tasks, return_exceptions=True)

    await engine.dispose()
    logger.info("Shutdown complete.")


# ─── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SENTINEL Security Telemetry API",
    version="2.0.0",
    lifespan=lifespan,
)

from routers.settings import router as settings_router
app.include_router(settings_router, prefix="/api")

from routers.prompt_triage import router as prompt_triage_router
app.include_router(prompt_triage_router, prefix="/api")

from routers.compliance import router as compliance_router
app.include_router(compliance_router, prefix="/api")


_default_origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]
_extra_origins = os.environ.get("SENTINEL_CORS_ORIGINS", "")
_allowed_origins = _default_origins + [o.strip() for o in _extra_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ⚡ Bolt: Compress large JSON responses (like proxy history or large topologies)
# to massively reduce network transit time.
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ─── Global Exception Handler (Anti-Silent-Failure Middleware) ────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    logger.error("Unhandled server exception on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": str(exc) if os.environ.get("SENTINEL_DEBUG") else "An unexpected error occurred",
        }
    )

# ─── Pydantic Schemas ─────────────────────────────────────────────────────────

from core.schemas import (
    TargetCreate, TargetUpdate, JobCreate, FindingUpdate, 
    ScopeRuleCreate, IngestRequest, AITriageRequest, ExploitTestRequest,
    ExploitActionRequest, ExploitStopRequest, OASTSettingsUpdate,
    RemediationRequest, EvasionSettingsUpdate
)

# ═══════════════════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

# ───── Auth ────────────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(username: str = Form(...), password: str = Form(...)):
    # Placeholder auth — real JWT implementation pending (see CLAUDE.md roadmap)
    raise HTTPException(status_code=501, detail="Authentication not yet implemented")


# ───── Health ──────────────────────────────────────────────────────────────────

@app.get("/api/health")

async def health():
    sys_stats = orchestrator.get_system_stats()
    return {
        "status": "online",
        "version": "2.0.0",
        "active_jobs": sys_stats["active_jobs"],
        "ws_connections": manager.count,
        "system": sys_stats,
        "resource_governor": resource_governor.get_status(),
        "feed_sync": feed_sync.status,
        "ai_triage": ai_triage.config,
    }


@app.get("/api/system/resources")
async def system_resources():
    return resource_governor.get_status()


@app.get("/api/settings/oast")
async def get_oast_settings_endpoint():
    return await get_oast_settings_service()


@app.post("/api/settings/oast")
async def update_oast_settings_endpoint(payload: OASTSettingsUpdate):
    settings = await update_oast_settings_service(payload)
    await reconfigure_oob_poller()
    return settings


@app.post("/api/shutdown")
async def shutdown(background_tasks: BackgroundTasks):
    logger.info("Shutdown requested. Initiating graceful shutdown...")

    def kill_process():
        import time
        import signal
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGINT)

    background_tasks.add_task(kill_process)
    return {"status": "shutting_down", "message": "Graceful shutdown initiated."}


@app.post("/api/system/hibernate", status_code=202)
async def request_hibernation():
    return await request_hibernation_service(HIBERNATE_SIGNAL_FILE)


# ───── Targets CRUD ───────────────────────────────────────────────────────────

@app.get("/api/targets")
async def list_targets():
    async with AsyncSessionLocal() as session:
        return await list_targets_service(session)


@app.post("/api/targets", status_code=201)
async def create_target(req: TargetCreate):
    async with AsyncSessionLocal() as session:
        return await create_target_service(req, session)


@app.get("/api/targets/{target_id}")
async def get_target(target_id: str):
    async with AsyncSessionLocal() as session:
        return await get_target_service(target_id, session)


@app.put("/api/targets/{target_id}")
async def update_target(target_id: str, req: TargetUpdate):
    async with AsyncSessionLocal() as session:
        return await update_target_service(target_id, req, session)


@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: str):
    async with AsyncSessionLocal() as session:
        return await delete_target_service(target_id, session)


@app.get("/api/topology")
async def get_topology(target_id: str):
    async with AsyncSessionLocal() as session:
        return await get_topology_service(target_id, session)


@app.get("/api/targets/{target_id}/routes")
async def get_target_routes(target_id: str):
    async with AsyncSessionLocal() as session:
        return await get_target_routes_service(target_id, session)


@app.get("/api/targets/{target_id}/triage")
async def get_target_ai_triage(target_id: str):
    async with AsyncSessionLocal() as session:
        return await get_target_ai_triage_service(target_id, session)


@app.get("/api/targets/{target_id}/logic-map")
async def get_target_logic_map(target_id: str):
    async with AsyncSessionLocal() as session:
        return await get_target_logic_map_service(target_id, session)


@app.get("/api/targets/{target_id}/dlp")
async def list_dlp_findings(target_id: str):
    async with AsyncSessionLocal() as session:
        return await list_dlp_findings_service(target_id, session)


@app.get("/api/targets/{target_id}/parameters")
async def list_discovered_parameters(target_id: str):
    async with AsyncSessionLocal() as session:
        return await list_discovered_parameters_service(target_id, session)


# ───── Jobs ────────────────────────────────────────────────────────────────────

@app.get("/api/jobs")
async def list_jobs(
    target_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
):
    async with AsyncSessionLocal() as session:
        return await list_jobs_service(target_id, status, limit, session)


@app.post("/api/jobs", status_code=201)
async def create_job(req: JobCreate):
    async with AsyncSessionLocal() as session:
        return await create_job_service(req, session)


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    async with AsyncSessionLocal() as session:
        return await get_job_service(job_id, session)


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    cancelled = await orchestrator.cancel_job(job_id)
    if cancelled:
        return {"status": "cancelled"}
    raise HTTPException(status_code=404, detail="Job not found or already completed")


# ───── Findings ────────────────────────────────────────────────────────────────

@app.get("/api/findings")
async def list_findings(
    target_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "first_seen",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 25,
):
    async with AsyncSessionLocal() as session:
        return await list_findings_service(
            target_id, severity, status, category, search,
            sort_by, sort_order, page, page_size, session
        )


@app.put("/api/findings/{finding_id}")
async def update_finding(finding_id: str, req: FindingUpdate):
    async with AsyncSessionLocal() as session:
        return await update_finding_service(finding_id, req, session)


@app.get("/api/findings/stats")
async def findings_stats(target_id: Optional[str] = None):
    async with AsyncSessionLocal() as session:
        return await get_findings_stats_service(target_id, session)


# ───── Data Ingestion ──────────────────────────────────────────────────────────

@app.post("/api/ingest")
async def ingest_data(req: IngestRequest):
    return await ingest_data_service(req)


# ───── Export ──────────────────────────────────────────────────────────────────

@app.get("/api/export/{fmt}")
async def export_data(fmt: str, target_id: Optional[str] = None):
    async with AsyncSessionLocal() as session:
        findings_data = await export_data_service(target_id, session)

    if fmt == "csv":
        from core.exporter import export_findings_csv
        content = export_findings_csv(findings_data)
        return PlainTextResponse(
            content, media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinel_findings.csv"},
        )
    elif fmt == "json":
        from core.exporter import export_findings_json
        content = export_findings_json(findings_data)
        return PlainTextResponse(
            content, media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=sentinel_findings.json"},
        )
    elif fmt == "html":
        from core.exporter import export_findings_html
        content = export_findings_html(findings_data)
        return HTMLResponse(content)

    raise HTTPException(status_code=400, detail="Invalid format. Use csv, json, or html.")


@app.get("/api/reports/{scan_id}/download")
async def download_report(scan_id: str):
    try:
        from services.reporting import ReportGenerator
        reports = await ReportGenerator.generate_scan_report(scan_id)
        return HTMLResponse(
            content=reports["html"],
            headers={
                "Content-Disposition": f"attachment; filename=sentinel_report_{scan_id}.html"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ───── Scope Rules ─────────────────────────────────────────────────────────────

@app.get("/api/scope")
async def list_scope_rules():
    async with AsyncSessionLocal() as session:
        return await list_scope_rules_service(session)


@app.post("/api/scope", status_code=201)
async def create_scope_rule(req: ScopeRuleCreate):
    async with AsyncSessionLocal() as session:
        return await create_scope_rule_service(req, session)


@app.delete("/api/scope/{rule_id}")
async def delete_scope_rule(rule_id: str):
    async with AsyncSessionLocal() as session:
        return await delete_scope_rule_service(rule_id, session)


# ───── Feed Sync ───────────────────────────────────────────────────────────────

@app.get("/api/feeds")
async def get_feed_status():
    return feed_sync.status


@app.post("/api/feeds/sync")
async def trigger_feed_sync():
    result = await feed_sync.sync_now()
    return result


@app.get("/api/feeds/templates")
async def list_feed_templates(source: Optional[str] = None, severity: Optional[str] = None):
    return await feed_sync.get_templates(source=source, severity=severity)


# ───── JS Analyzer ─────────────────────────────────────────────────────────────

@app.post("/api/analyze/js")
async def analyze_js(target_id: str, url: str):
    async with AsyncSessionLocal() as session:
        return await analyze_js_service(target_id, url, session)


@app.get("/api/js-findings")
async def list_js_findings(target_id: Optional[str] = None, finding_type: Optional[str] = None, limit: int = 100):
    async with AsyncSessionLocal() as session:
        return await list_js_findings_service(target_id, finding_type, limit, session)


# ───── Fingerprint Engine ─────────────────────────────────────────────────────

@app.post("/api/fingerprint")
async def fingerprint_host_endpoint(host: str, port: int = 443):
    return await fingerprint_host_endpoint_service(host, port)


@app.get("/api/clusters")
async def get_clusters():
    return await get_clusters_service()


# ───── Fuzzer ──────────────────────────────────────────────────────────────────

@app.post("/api/fuzz")
async def trigger_fuzz(target_id: str, url: str, fuzz_types: Optional[List[str]] = None):
    return await trigger_fuzz_service(target_id, url, fuzz_types)


# ───── AI Triage ───────────────────────────────────────────────────────────────

@app.post("/api/ai/triage")
async def ai_triage_endpoint(req: AITriageRequest):
    return await ai_triage_endpoint_service(req)


@app.post("/api/ai/poc/{finding_id}")
async def ai_poc_endpoint(finding_id: str):
    return await ai_poc_endpoint_service(finding_id)


@app.get("/api/ai/status")
async def ai_status():
    return await ai_status_service()
# ───── Evasion Settings ──────────────────────────────────────────────────────────

@app.get("/api/settings/evasion")
async def get_evasion_settings_endpoint():
    from core.evasion_manager import load_evasion_settings
    return load_evasion_settings()


@app.post("/api/settings/evasion")
async def update_evasion_settings_endpoint(payload: EvasionSettingsUpdate):
    from core.evasion_manager import update_evasion_settings
    return update_evasion_settings(
        custom_headers=payload.custom_headers,
        sqli_strategy=payload.sqli_strategy,
        xss_strategy=payload.xss_strategy,
        lfi_strategy=payload.lfi_strategy
    )


# ───── Tool Registry ──────────────────────────────────────────────────────────

@app.get("/api/tools")
async def get_tool_registry():
    registry = load_tool_registry()
    return registry.get("tools", {})


# ───── Exploit Engine ──────────────────────────────────────────────────────────

@app.post("/api/exploit/test")
async def run_exploit_test(req: ExploitTestRequest):
    return await run_exploit_test_service(req, manager.broadcast)


@app.post("/api/exploit/action")
async def run_exploit_operator_action(req: ExploitActionRequest):
    return await run_exploit_operator_action_service(req)


@app.post("/api/exploit/stop")
async def stop_exploit(req: Optional[ExploitStopRequest] = None):
    return await stop_exploit_service(req)


# ───── WebSocket ───────────────────────────────────────────────────────────────

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    
    # Asynchronous Redis Pub/Sub subscription wrapper
    import os
    import json
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    async def redis_listener():
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(redis_url)
            pubsub = r.pubsub()
            await pubsub.subscribe("sentinel:updates")
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"].decode("utf-8") if isinstance(message["data"], bytes) else message["data"])
                        await websocket.send_json(data)
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Redis PubSub listener bypassed/offline: {e}")
            
    listener_task = asyncio.create_task(redis_listener())
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
    finally:
        listener_task.cancel()


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
