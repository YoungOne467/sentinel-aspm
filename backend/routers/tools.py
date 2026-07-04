from __future__ import annotations

import logging
import os
import yaml
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse, HTMLResponse


from core.database import AsyncSessionLocal
from core.feed_sync import feed_sync
from core.schemas import (
    ScopeRuleCreate, IngestRequest, AITriageRequest, ExploitTestRequest,
    ExploitActionRequest, ExploitStopRequest, EvasionSettingsUpdate
)
from services.scanner import (
    list_scope_rules_service,
    create_scope_rule_service,
    delete_scope_rule_service,
    analyze_js_service,
    list_js_findings_service,
    fingerprint_host_endpoint_service,
    get_clusters_service,
    trigger_fuzz_service,
    ai_triage_endpoint_service,
    ai_poc_endpoint_service,
    ai_status_service,
    run_exploit_test_service,
    run_exploit_operator_action_service,
    stop_exploit_service,
    ingest_data_service,
    export_data_service,
)

logger = logging.getLogger("sentinel.routers.tools")
router = APIRouter()

TOOL_REGISTRY_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "core", "tool_registry.yaml")

_broadcast_fn = None

def init_tools_router(broadcast_fn):
    global _broadcast_fn
    _broadcast_fn = broadcast_fn

def load_tool_registry() -> dict:
    try:
        with open(TOOL_REGISTRY_PATH, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Could not load tool registry: %s", e)
        return {"tools": {}, "settings": {}}

@router.get("/api/scope")
async def list_scope_rules():
    async with AsyncSessionLocal() as session:
        return await list_scope_rules_service(session)

@router.post("/api/scope", status_code=201)
async def create_scope_rule(req: ScopeRuleCreate):
    async with AsyncSessionLocal() as session:
        return await create_scope_rule_service(req, session)

@router.delete("/api/scope/{rule_id}")
async def delete_scope_rule(rule_id: str):
    async with AsyncSessionLocal() as session:
        return await delete_scope_rule_service(rule_id, session)

@router.get("/api/feeds")
async def get_feed_status():
    return feed_sync.status

@router.post("/api/feeds/sync")
async def trigger_feed_sync():
    result = await feed_sync.sync_now()
    return result

@router.get("/api/feeds/templates")
async def list_feed_templates(source: Optional[str] = None, severity: Optional[str] = None):
    return await feed_sync.get_templates(source=source, severity=severity)

@router.post("/api/analyze/js")
async def analyze_js(target_id: str, url: str):
    async with AsyncSessionLocal() as session:
        return await analyze_js_service(target_id, url, session)

@router.get("/api/js-findings")
async def list_js_findings(target_id: Optional[str] = None, finding_type: Optional[str] = None, limit: int = 100):
    async with AsyncSessionLocal() as session:
        return await list_js_findings_service(target_id, finding_type, limit, session)

@router.post("/api/fingerprint")
async def fingerprint_host_endpoint(host: str, port: int = 443):
    return await fingerprint_host_endpoint_service(host, port)

@router.get("/api/clusters")
async def get_clusters():
    return await get_clusters_service()

@router.post("/api/fuzz")
async def trigger_fuzz(target_id: str, url: str, fuzz_types: Optional[List[str]] = None):
    return await trigger_fuzz_service(target_id, url, fuzz_types)

@router.post("/api/ai/triage")
async def ai_triage_endpoint(req: AITriageRequest):
    return await ai_triage_endpoint_service(req)

@router.post("/api/ai/poc/{finding_id}")
async def ai_poc_endpoint(finding_id: str):
    return await ai_poc_endpoint_service(finding_id)

@router.get("/api/ai/status")
async def ai_status():
    return await ai_status_service()

@router.get("/api/settings/evasion")
async def get_evasion_settings_endpoint():
    from core.evasion_manager import load_evasion_settings
    return load_evasion_settings()

@router.post("/api/settings/evasion")
async def update_evasion_settings_endpoint(payload: EvasionSettingsUpdate):
    from core.evasion_manager import update_evasion_settings
    return update_evasion_settings(
        custom_headers=payload.custom_headers,
        sqli_strategy=payload.sqli_strategy,
        xss_strategy=payload.xss_strategy,
        lfi_strategy=payload.lfi_strategy
    )

@router.get("/api/tools")
async def get_tool_registry():
    registry = load_tool_registry()
    return registry.get("tools", {})

@router.post("/api/exploit/test")
async def run_exploit_test(req: ExploitTestRequest):
    broadcast = _broadcast_fn if _broadcast_fn else lambda x: None
    return await run_exploit_test_service(req, broadcast)

@router.post("/api/exploit/action")
async def run_exploit_operator_action(req: ExploitActionRequest):
    return await run_exploit_operator_action_service(req)

@router.post("/api/exploit/stop")
async def stop_exploit(req: Optional[ExploitStopRequest] = None):
    return await stop_exploit_service(req)

@router.post("/api/ingest")
async def ingest_data(req: IngestRequest):
    return await ingest_data_service(req)

@router.get("/api/export/{fmt}")
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

@router.get("/api/reports/{scan_id}/download")
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

from pydantic import BaseModel
from typing import Dict

class AuthContextInjectPayload(BaseModel):
    headers: Dict[str, str]
    cookies: Dict[str, str]

@router.post("/api/auth-context/inject")
async def inject_auth_context(payload: AuthContextInjectPayload):
    from core.auth_context import global_auth_context
    sanitized_headers = {}
    for k, v in payload.headers.items():
        k_clean = k.strip()
        v_clean = str(v).strip()
        
        # Strip prefixes like "Cookie: " or "Authorization: " if accidentally included in value
        if v_clean.lower().startswith("cookie:"):
            v_clean = v_clean[len("cookie:"):].strip()
        if v_clean.lower().startswith("authorization:"):
            v_clean = v_clean[len("authorization:"):].strip()
            
        sanitized_headers[k_clean] = v_clean

    global_auth_context.set_context(sanitized_headers, payload.cookies)
    return {"status": "success", "message": "Auth context injected successfully"}

@router.delete("/api/auth-context/clear")
async def clear_auth_context():
    from core.auth_context import global_auth_context
    global_auth_context.clear()
    return {"status": "success", "message": "Auth context cleared successfully"}

@router.get("/api/auth-context/status")
async def get_auth_context_status():
    from core.auth_context import global_auth_context
    headers = global_auth_context.get_headers()
    cookies = global_auth_context.get_cookies()
    return {
        "locked": len(headers) > 0 or len(cookies) > 0,
        "headers_count": len(headers),
        "cookies_count": len(cookies)
    }

