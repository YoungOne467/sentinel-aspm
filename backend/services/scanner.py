import asyncio
import logging
import json
import uuid
import hashlib
import sys
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import HTTPException

from sqlalchemy import select, desc, asc, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import (
    Target, Job, Finding, ScopeRule, FeedTemplate,
    JSFinding, InfraCluster, CrawledURL, DiscoveredSubdomain,
    ShadowAPI, DLPFinding, DiscoveredParameter, gen_id
)
from core.database import AsyncSessionLocal, batch_writer
from core.schemas import (
    TargetCreate, TargetUpdate, JobCreate, FindingUpdate, 
    ScopeRuleCreate, IngestRequest, AITriageRequest, ExploitTestRequest,
    ExploitActionRequest, ExploitStopRequest, OASTSettingsUpdate
)
from core.scope_manager import scope_manager
from core.http_pool import HTTPClientPool
from core.js_analyzer import js_analyzer
from core.fingerprint_engine import fingerprint_engine
from core.fuzzer_orchestrator import fuzzer_orchestrator
from core.ai_triage import ai_triage
from core.parser import ingest_findings
from core.oast_listener import get_oast_settings, update_oast_settings

logger = logging.getLogger(__name__)

# Concurrency semaphore for active scanning loops to prevent socket exhaustion
fuzzer_semaphore = asyncio.Semaphore(15)

# Shared in-memory operational state for active exploiter instances
global_state = {
    "active_exploiter": None,
    "exploit_result": None
}


def _legacy_main_module():
    return sys.modules.get("main")


def _set_active_exploiter(exploiter) -> None:
    global_state["active_exploiter"] = exploiter
    main_module = _legacy_main_module()
    if main_module is not None:
        setattr(main_module, "_active_exploiter", exploiter)


def _set_exploit_result(result) -> None:
    global_state["exploit_result"] = result
    main_module = _legacy_main_module()
    if main_module is not None:
        setattr(main_module, "_exploit_result", result)


def _get_exploit_result():
    if global_state.get("exploit_result"):
        return global_state["exploit_result"]
    main_module = _legacy_main_module()
    return getattr(main_module, "_exploit_result", None) if main_module is not None else None


def _get_active_exploiter():
    if global_state.get("active_exploiter"):
        return global_state["active_exploiter"]
    main_module = _legacy_main_module()
    return getattr(main_module, "_active_exploiter", None) if main_module is not None else None

# ─── Helper Functions ─────────────────────────────────────────────────────────

def clean_host_and_port(host: str, port: Optional[int]) -> tuple[str, Optional[int]]:
    host = host.strip()
    if not host.startswith(("http://", "https://", "ftp://", "//")):
        parsed = urlparse("//" + host)
    else:
        parsed = urlparse(host)
    
    netloc = parsed.netloc or parsed.path
    if ":" in netloc:
        parts = netloc.rsplit(":", 1)
        clean_host = parts[0]
        try:
            parsed_port = int(parts[1])
            if port is None:
                port = parsed_port
        except ValueError:
            pass
    else:
        clean_host = netloc
        
    clean_host = clean_host.strip("[]").split("/")[0]
    return clean_host, port

# ─── Target Services ──────────────────────────────────────────────────────────

async def list_targets_service(session: AsyncSession) -> List[Dict[str, Any]]:
    result = await session.execute(select(Target).order_by(desc(Target.risk_score)))
    targets = result.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "host": t.host,
            "port": t.port,
            "tags": t.tags or [],
            "notes": t.notes,
            "tech_stack": t.tech_stack or [],
            "risk_score": t.risk_score or 0.0,
            "known_cves": t.known_cves or [],
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        }
        for t in targets
    ]

async def create_target_service(req: TargetCreate, session: AsyncSession) -> Dict[str, Any]:
    clean_host, port = clean_host_and_port(req.host, req.port)
    
    if not scope_manager.is_in_scope(clean_host):
        raise HTTPException(status_code=403, detail=f"Host '{clean_host}' is out of scope")

    target = Target(
        id=gen_id(),
        name=req.name,
        host=clean_host,
        port=port,
        tags=req.tags or [],
        notes=req.notes or "",
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return {"id": target.id, "name": target.name, "host": target.host}

async def get_target_service(target_id: str, session: AsyncSession) -> Dict[str, Any]:
    target = await session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return {
        "id": target.id,
        "name": target.name,
        "host": target.host,
        "port": target.port,
        "tags": target.tags or [],
        "notes": target.notes,
        "tech_stack": target.tech_stack or [],
        "risk_score": target.risk_score or 0.0,
        "known_cves": target.known_cves or [],
        "created_at": target.created_at.isoformat() if target.created_at else None,
    }

async def update_target_service(target_id: str, req: TargetUpdate, session: AsyncSession) -> Dict[str, Any]:
    target = await session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    if req.name is not None:
        target.name = req.name
    
    current_port = req.port if req.port is not None else target.port
    if req.host is not None:
        clean_host, port = clean_host_and_port(req.host, current_port)
        if not scope_manager.is_in_scope(clean_host):
            raise HTTPException(status_code=403, detail=f"Host '{clean_host}' is out of scope")
        target.host = clean_host
        target.port = port
    elif req.port is not None:
        target.port = req.port
        
    if req.tags is not None:
        target.tags = req.tags
    if req.notes is not None:
        target.notes = req.notes
        
    target.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    await session.commit()
    return {"status": "updated"}

async def delete_target_service(target_id: str, session: AsyncSession) -> Dict[str, Any]:
    target = await session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await session.delete(target)
    await session.commit()
    return {"status": "deleted"}

async def get_topology_service(target_id: str, session: AsyncSession) -> Dict[str, Any]:
    target = await session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    subdomains_res = await session.execute(
        select(Finding).where(
            Finding.target_id == target_id,
            Finding.category == "subdomain_recon"
        )
    )
    subdomains = subdomains_res.scalars().all()

    disc_subs_res = await session.execute(
        select(DiscoveredSubdomain).where(
            DiscoveredSubdomain.target_id == target_id
        )
    )
    disc_subdomains = disc_subs_res.scalars().all()
    
    crawled_urls_res = await session.execute(
        select(CrawledURL).where(
            CrawledURL.target_id == target_id
        )
    )
    crawled_urls = crawled_urls_res.scalars().all()
    
    nodes = []
    edges = []
    
    nodes.append({
        "id": "root",
        "id_actual": target.id,
        "target_id": target.id,
        "label": target.host,
        "type": "root",
        "is_new": False,
        "has_alert": False,
        "risk_score": target.risk_score or 0.0,
        "tech_stack": target.tech_stack or [],
        "known_cves": target.known_cves or [],
        "shadow_apis": []
    })
    
    subdomain_dict = {}
    for ds in disc_subdomains:
        s_name = ds.subdomain.lower().strip()
        subdomain_dict[s_name] = {
            "id": s_name,
            "target_id": target.id,
            "label": ds.subdomain,
            "type": "subdomain",
            "is_new": ds.is_new,
            "has_alert": False,
            "risk_score": ds.risk_score or 0.0,
            "tech_stack": ds.tech_stack or [],
            "known_cves": [],
            "shadow_apis": []
        }

    for finding in subdomains:
        subdomain_name = None
        if finding.raw_data and isinstance(finding.raw_data, dict):
            subdomain_name = finding.raw_data.get("subdomain")
        if not subdomain_name:
            if finding.title.startswith("Discovered Subdomain: "):
                subdomain_name = finding.title.replace("Discovered Subdomain: ", "").strip()
            else:
                subdomain_name = finding.title.strip()
        
        if subdomain_name and subdomain_name != target.host:
            subdomain_name = subdomain_name.lower().strip()
            if subdomain_name not in subdomain_dict:
                subdomain_dict[subdomain_name] = {
                    "id": subdomain_name,
                    "target_id": target.id,
                    "label": subdomain_name,
                    "type": "subdomain",
                    "is_new": finding.is_new,
                    "has_alert": False,
                    "risk_score": 0.0,
                    "tech_stack": [],
                    "known_cves": [],
                    "shadow_apis": []
                }
    
    seen_subdomains = set(subdomain_dict.keys())
    for sub_node in subdomain_dict.values():
        sub_cves = []
        sub_apis = []
        sub_cve_ids = set()
        sub_api_routes = set()
        for c_url in crawled_urls:
            c_host = c_url.host.lower().strip()
            c_host_no_port = c_host.split(":")[0]
            if c_host == sub_node["id"] or c_host_no_port == sub_node["id"]:
                for cve in (c_url.known_cves or []):
                    if cve["cve_id"] not in sub_cve_ids:
                        sub_cves.append(cve)
                        sub_cve_ids.add(cve["cve_id"])
                
                s_api_res = await session.execute(
                    select(ShadowAPI.route).where(ShadowAPI.crawled_url_id == c_url.id)
                )
                routes = s_api_res.scalars().all()
                for r in routes:
                    if r not in sub_api_routes:
                        sub_apis.append(r)
                        sub_api_routes.add(r)
        sub_node["known_cves"] = sub_cves
        sub_node["shadow_apis"] = sub_apis

        nodes.append(sub_node)
        edges.append({
            "source": "root",
            "target": sub_node["id"]
        })
    
    for c_url in crawled_urls:
        try:
            parsed = urlparse(c_url.url)
            path_label = parsed.path
            if parsed.query:
                path_label += f"?{parsed.query}"
            if not path_label:
                path_label = "/"
        except Exception:
            path_label = c_url.url
        
        s_api_res = await session.execute(
            select(ShadowAPI.route).where(ShadowAPI.crawled_url_id == c_url.id)
        )
        routes = s_api_res.scalars().all()
            
        nodes.append({
            "id": c_url.id,
            "target_id": c_url.target_id,
            "label": path_label,
            "type": "endpoint",
            "is_new": c_url.is_new,
            "has_alert": c_url.has_alert,
            "url": c_url.url,
            "risk_score": c_url.risk_score or 0.0,
            "tech_stack": c_url.tech_stack or [],
            "known_cves": c_url.known_cves or [],
            "shadow_apis": list(routes)
        })
        
        c_host = c_url.host.lower().strip()
        c_host_no_port = c_host.split(":")[0]
        
        parent_id = "root"
        if c_host in seen_subdomains:
            parent_id = c_host
        elif c_host_no_port in seen_subdomains:
            parent_id = c_host_no_port
        
        edges.append({
            "source": parent_id,
            "target": c_url.id
        })
        
    return {
        "nodes": nodes,
        "edges": edges
    }

async def get_target_routes_service(target_id: str, session: AsyncSession) -> List[Dict[str, Any]]:
    result = await session.execute(
        select(ShadowAPI.route, CrawledURL.url)
        .join(CrawledURL, ShadowAPI.crawled_url_id == CrawledURL.id)
        .where(CrawledURL.target_id == target_id)
        .order_by(ShadowAPI.created_at.desc())
    )
    items = result.all()
    return [
        {
            "route": item[0],
            "source_url": item[1]
        }
        for item in items
    ]

async def get_target_ai_triage_service(target_id: str, session: AsyncSession) -> Dict[str, Any]:
    summary = await ai_triage.generate_node_summary(target_id, session)
    return {"summary": summary}

async def get_target_logic_map_service(target_id: str, session: AsyncSession) -> Dict[str, Any]:
    target = await session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    if target.logic_map:
        return {"logic_map": target.logic_map}
    
    from core.logic_mapper import aggregate_session_traffic
    traffic = await aggregate_session_traffic(target_id)
    logic_map_str = await ai_triage.generate_state_machine(traffic)
    
    target.logic_map = logic_map_str
    await session.commit()
    return {"logic_map": logic_map_str}

async def list_dlp_findings_service(target_id: str, session: AsyncSession) -> List[Dict[str, Any]]:
    result = await session.execute(
        select(DLPFinding, CrawledURL.url)
        .join(CrawledURL, DLPFinding.crawled_url_id == CrawledURL.id)
        .where(CrawledURL.target_id == target_id)
        .order_by(DLPFinding.created_at.desc())
    )
    items = result.all()
    return [
        {
            "id": f.id,
            "crawled_url_id": f.crawled_url_id,
            "url": url,
            "finding_type": f.finding_type,
            "value": f.value,
            "context": f.context,
            "compliance_tags": f.compliance_tags or [],
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f, url in items
    ]

async def list_discovered_parameters_service(target_id: str, session: AsyncSession) -> List[Dict[str, Any]]:
    result = await session.execute(
        select(DiscoveredParameter, CrawledURL.url)
        .join(CrawledURL, DiscoveredParameter.crawled_url_id == CrawledURL.id)
        .where(CrawledURL.target_id == target_id)
        .order_by(DiscoveredParameter.created_at.desc())
    )
    items = result.all()
    return [
        {
            "id": p.id,
            "crawled_url_id": p.crawled_url_id,
            "url": url,
            "name": p.name,
            "source": p.source,
            "context": p.context,
            "confidence": p.confidence,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p, url in items
    ]

# ─── Job Services ─────────────────────────────────────────────────────────────

async def list_jobs_service(target_id: Optional[str], status: Optional[str], limit: int, session: AsyncSession) -> List[Dict[str, Any]]:
    query = select(Job).order_by(desc(Job.created_at)).limit(limit)
    if target_id:
        query = query.where(Job.target_id == target_id)
    if status:
        query = query.where(Job.status == status)
    result = await session.execute(query)
    jobs = result.scalars().all()
    return [
        {
            "id": j.id,
            "target_id": j.target_id,
            "tool_name": j.tool_name,
            "command": j.command,
            "status": j.status,
            "exit_code": j.exit_code,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            "created_at": j.created_at.isoformat() if j.created_at else None,
        }
        for j in jobs
    ]

async def run_cognitive_pipeline(job_id: str, target_id: str):
    from core.orchestrator import orchestrator
    from core.database import AsyncSessionLocal
    from core.models import Job, Target
    from datetime import datetime, timezone
    from sqlalchemy import update
    import logging

    logger = logging.getLogger("sentinel.cognitive_pipeline")

    async def update_status(status: str, **kwargs):
        try:
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
            await orchestrator._broadcast_msg({
                "type": "job_status",
                "job_id": job_id,
                "status": status,
                "tool": "Cognitive AI Recon",
                **kwargs
            })
        except Exception as e:
            logger.error("Failed to update status for job %s: %s", job_id, e)

    # Wrap the entire execution in a try-except to prevent silent background failure
    try:
        # 1. Update job to running
        logger.info("[Cognitive Engine] Starting pipeline job %s for target %s", job_id, target_id)
        print(f"[Cognitive Engine] Starting pipeline job {job_id} for target {target_id}")
        await update_status("running", started_at=datetime.now(timezone.utc))

        async with AsyncSessionLocal() as session:
            target = await session.get(Target, target_id)
            if not target:
                logger.error("[Cognitive Engine] Target not found for target_id %s", target_id)
                print(f"[Cognitive Engine] Target not found for target_id {target_id}")
                await update_status("failed", completed_at=datetime.now(timezone.utc), stderr="Target not found")
                return
            host = target.host

        msg = f"[Cognitive Engine] Launching Autonomous Cognitive Engine on Target {host}..."
        logger.info("%s", msg)
        print(msg)
        await orchestrator._broadcast_msg({
            "type": "terminal_output",
            "job_id": job_id,
            "stream": "stdout",
            "line": msg,
            "tool": "Cognitive AI Recon"
        })

        # Import CognitiveEngineService and Dispatcher inside the try block to catch import errors (e.g. tiktoken)
        from core.cognitive_engine import CognitiveEngineService, Dispatcher

        msg = "[Cognitive Engine] Analyzing target telemetry and endpoint configurations with Phi-4-mini..."
        logger.info("%s", msg)
        print(msg)
        await orchestrator._broadcast_msg({
            "type": "terminal_output",
            "job_id": job_id,
            "stream": "stdout",
            "line": msg,
            "tool": "Cognitive AI Recon"
        })

        engine = CognitiveEngineService()
        plan = await engine.analyze_target_telemetry(target_id, job_id=job_id)
        
        if not plan or not plan.actions:
            msg = "[Cognitive Engine] No actions generated or telemetry analysis returned empty."
            logger.info("%s", msg)
            print(msg)
            await orchestrator._broadcast_msg({
                "type": "terminal_output",
                "job_id": job_id,
                "stream": "stdout",
                "line": msg,
                "tool": "Cognitive AI Recon"
            })
            await update_status("completed", completed_at=datetime.now(timezone.utc))
            return

        msg = f"[Cognitive Engine] Successfully formulated AttackPlan with {len(plan.actions)} actions."
        logger.info("%s", msg)
        print(msg)
        await orchestrator._broadcast_msg({
            "type": "terminal_output",
            "job_id": job_id,
            "stream": "stdout",
            "line": msg,
            "tool": "Cognitive AI Recon"
        })

        # 3. Dispatch Plan
        dispatcher = Dispatcher()

        # Wrap evaluate_response to catch findings and log to WebSocket & console
        original_evaluate = dispatcher._evaluate_response
        def wrapped_evaluate(t_id: str, act, response):
            finding = original_evaluate(t_id, act, response)
            if finding:
                confirm_msg = f"[🔴 VULNERABILITY CONFIRMED] Verified vulnerability: {finding.title} (Severity: {finding.severity})"
                logger.warning("%s", confirm_msg)
                print(confirm_msg)
                asyncio.create_task(orchestrator._broadcast_msg({
                    "type": "terminal_output",
                    "job_id": job_id,
                    "stream": "stdout",
                    "line": confirm_msg,
                    "tool": "Cognitive AI Recon"
                }))
            return finding
        dispatcher._evaluate_response = wrapped_evaluate

        # Wrap execute/dispatch to stream logs to terminal console & WebSocket
        original_execute = dispatcher._execute_action
        async def wrapped_execute(target_id: str, action, client):
            log_line = f"[Dispatcher] Testing logic hypothesis: '{action.logic_flaw_hypothesis}' via {action.action_type} targeting {action.target_element}"
            logger.info("%s", log_line)
            print(log_line)
            await orchestrator._broadcast_msg({
                "type": "terminal_output",
                "job_id": job_id,
                "stream": "stdout",
                "line": log_line,
                "tool": "Cognitive AI Recon"
            })
            await original_execute(target_id, action, client)

        dispatcher._execute_action = wrapped_execute
        
        logger.info("[Cognitive Engine] Dispatching AttackPlan...")
        print("[Cognitive Engine] Dispatching AttackPlan...")
        await dispatcher.dispatch_plan(target_id, plan)

        msg = "[Cognitive Engine] Autonomous cognitive verification run completed."
        logger.info("%s", msg)
        print(msg)
        await orchestrator._broadcast_msg({
            "type": "terminal_output",
            "job_id": job_id,
            "stream": "stdout",
            "line": msg,
            "tool": "Cognitive AI Recon"
        })

        await update_status("completed", completed_at=datetime.now(timezone.utc))

    except Exception as e:
        error_msg = f"Cognitive pipeline job failed: {e}"
        logger.error("%s", error_msg, exc_info=True)
        print(f"[ERROR] {error_msg}")
        await update_status("failed", completed_at=datetime.now(timezone.utc), stderr=str(e))
        try:
            await orchestrator._broadcast_msg({
                "type": "terminal_output",
                "job_id": job_id,
                "stream": "stderr",
                "line": f"[Cognitive Engine Error] Job failed: {e}",
                "tool": "Cognitive AI Recon"
            })
        except Exception as ws_err:
            logger.error("Failed to broadcast failure message: %s", ws_err)

async def create_job_service(req: JobCreate, session: AsyncSession) -> Dict[str, Any]:
    target = await session.get(Target, req.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if req.scan_profile == "Cognitive AI Recon":
        job_id = gen_id()
        job = Job(
            id=job_id,
            target_id=req.target_id,
            tool_name="Cognitive AI Recon",
            command="Autonomous Cognitive Engine Pipeline",
            status="queued",
        )
        session.add(job)
        await session.commit()

        # Run cognitive pipeline in the background
        asyncio.create_task(run_cognitive_pipeline(job_id, req.target_id), name=f"cognitive_engine_{job_id}")
        return {"job_id": job_id, "status": "queued"}

    from core.pipeline_manager import run_pipeline, PROFILES
    if req.scan_profile not in PROFILES:
        raise HTTPException(status_code=400, detail=f"Invalid scan profile: {req.scan_profile}")

    job_id = gen_id()
    job = Job(
        id=job_id,
        target_id=req.target_id,
        tool_name=req.scan_profile,
        command=f"Automated Pipeline: {req.scan_profile}",
        status="queued",
    )
    session.add(job)
    await session.commit()

    asyncio.create_task(run_pipeline(job_id, req.scan_profile, req.target_id))
    return {"job_id": job_id, "status": "queued"}

async def get_job_service(job_id: str, session: AsyncSession) -> Dict[str, Any]:
    job = await session.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job.id,
        "target_id": job.target_id,
        "tool_name": job.tool_name,
        "command": job.command,
        "status": job.status,
        "exit_code": job.exit_code,
        "stdout": job.stdout,
        "stderr": job.stderr,
        "stdout_compressed": job.stdout_compressed,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }

# ─── Finding Services ─────────────────────────────────────────────────────────

async def list_findings_service(
    target_id: Optional[str], severity: Optional[str], status: Optional[str],
    category: Optional[str], search: Optional[str], sort_by: str, sort_order: str,
    page: int, page_size: int, session: AsyncSession
) -> Dict[str, Any]:
    query = select(Finding)
    count_query = select(func.count(Finding.id))

    filters = []
    if target_id:
        filters.append(Finding.target_id == target_id)
    if severity:
        filters.append(Finding.severity == severity)
    if status:
        filters.append(Finding.status == status)
    if category:
        filters.append(Finding.category == category)
    if search:
        like = f"%{search}%"
        filters.append(Finding.title.ilike(like) | Finding.description.ilike(like))

    for f in filters:
        query = query.where(f)
        count_query = count_query.where(f)

    sort_col = getattr(Finding, sort_by, Finding.first_seen)
    query = query.order_by(desc(sort_col) if sort_order == "desc" else asc(sort_col))

    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await session.execute(query)
    findings = result.scalars().all()

    return {
        "findings": [
            {
                "id": f.id,
                "job_id": f.job_id,
                "target_id": f.target_id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "evidence": f.evidence,
                "solution": f.solution,
                "status": f.status,
                "ai_triaged": f.ai_triaged,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            }
            for f in findings
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }

async def update_finding_service(finding_id: str, req: FindingUpdate, session: AsyncSession) -> Dict[str, Any]:
    finding = await session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if req.status:
        finding.status = req.status
    await session.commit()
    return {"status": "updated"}

async def get_findings_stats_service(target_id: Optional[str], session: AsyncSession) -> Dict[str, Any]:
    base_filter = Finding.target_id == target_id if target_id else True

    # Severity counts via SQL aggregation
    sev_result = await session.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(base_filter)
        .group_by(Finding.severity)
    )
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    for severity, count in sev_result.all():
        sev[severity] = count
        total += count
    sev["total"] = total

    # Status counts via SQL aggregation
    st_result = await session.execute(
        select(Finding.status, func.count(Finding.id))
        .where(base_filter)
        .group_by(Finding.status)
    )
    st = {"open": 0, "confirmed": 0, "false_positive": 0, "resolved": 0}
    for status, count in st_result.all():
        st[status] = count

    # Category counts via SQL aggregation
    cat_result = await session.execute(
        select(Finding.category, func.count(Finding.id))
        .where(base_filter)
        .group_by(Finding.category)
    )
    cats: Dict[str, int] = {}
    for category, count in cat_result.all():
        cats[category] = count

    return {"severity": sev, "status": st, "categories": cats}

# ─── Data Ingestion Services ──────────────────────────────────────────────────

async def ingest_data_service(req: IngestRequest) -> Dict[str, Any]:
    new_count = await ingest_findings(
        target_id=req.target_id,
        job_id=req.job_id,
        raw_output=req.raw_output,
        output_format=req.output_format,
    )
    return {"new_findings": new_count}

# ─── Export Services ──────────────────────────────────────────────────────────

async def export_data_service(target_id: Optional[str], session: AsyncSession) -> List[Dict[str, Any]]:
    query = select(Finding).order_by(desc(Finding.first_seen))
    if target_id:
        query = query.where(Finding.target_id == target_id)
    result = await session.execute(query)
    all_findings = result.scalars().all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
            "evidence": f.evidence,
            "solution": f.solution,
            "status": f.status,
            "first_seen": f.first_seen.isoformat() if f.first_seen else "",
            "last_seen": f.last_seen.isoformat() if f.last_seen else "",
        }
        for f in all_findings
    ]

# ─── Scope Services ───────────────────────────────────────────────────────────

async def list_scope_rules_service(session: AsyncSession) -> List[Dict[str, Any]]:
    result = await session.execute(select(ScopeRule).order_by(desc(ScopeRule.created_at)))
    return [
        {
            "id": r.id,
            "rule_type": r.rule_type,
            "pattern_type": r.pattern_type,
            "pattern": r.pattern,
            "description": r.description,
            "active": r.active,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in result.scalars().all()
    ]

async def create_scope_rule_service(req: ScopeRuleCreate, session: AsyncSession) -> Dict[str, Any]:
    rule = ScopeRule(
        id=gen_id(),
        rule_type=req.rule_type,
        pattern_type=req.pattern_type,
        pattern=req.pattern,
        description=req.description,
    )
    session.add(rule)
    await session.commit()
    await scope_manager.load_rules()
    return {"id": rule.id, "status": "created"}

async def delete_scope_rule_service(rule_id: str, session: AsyncSession) -> Dict[str, Any]:
    rule = await session.get(ScopeRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await session.delete(rule)
    await session.commit()
    await scope_manager.load_rules()
    return {"status": "deleted"}

# ─── JS Findings Services ─────────────────────────────────────────────────────

async def analyze_js_service(target_id: str, url: str, session: AsyncSession) -> Dict[str, Any]:
    target = await session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    stats = await js_analyzer.analyze_target(target_id, url)
    return stats

async def list_js_findings_service(target_id: Optional[str], finding_type: Optional[str], limit: int, session: AsyncSession) -> List[Dict[str, Any]]:
    query = select(JSFinding).order_by(desc(JSFinding.created_at)).limit(limit)
    if target_id:
        query = query.where(JSFinding.target_id == target_id)
    if finding_type:
        query = query.where(JSFinding.finding_type == finding_type)
    result = await session.execute(query)
    return [
        {
            "id": j.id,
            "target_id": j.target_id,
            "source_url": j.source_url,
            "finding_type": j.finding_type,
            "value": j.value,
            "context": j.context,
            "confidence": j.confidence,
            "created_at": j.created_at.isoformat() if j.created_at else None,
        }
        for j in result.scalars().all()
    ]

# ─── Fingerprint Services ─────────────────────────────────────────────────────

async def fingerprint_host_endpoint_service(host: str, port: int) -> Dict[str, Any]:
    return await fingerprint_engine.fingerprint_host(host, port)

async def get_clusters_service() -> List[Dict[str, Any]]:
    return await fingerprint_engine.get_clusters()

# ─── Fuzzer Services ──────────────────────────────────────────────────────────

async def trigger_fuzz_service(target_id: str, url: str, fuzz_types: Optional[List[str]]) -> Dict[str, Any]:
    results = await fuzzer_orchestrator.auto_fuzz(target_id, url, fuzz_types)
    return {"jobs": results}

# ─── AI Triage Services ────────────────────────────────────────────────────────

async def ai_triage_endpoint_service(req: AITriageRequest) -> Dict[str, Any]:
    results = await ai_triage.batch_triage(req.finding_ids)
    return {"results": results}

async def ai_poc_endpoint_service(finding_id: str) -> Dict[str, Any]:
    return await ai_triage.draft_poc(finding_id)

async def ai_status_service() -> Dict[str, Any]:
    available = await ai_triage.check_availability()
    return {"available": available, "config": ai_triage.config}

# ─── Exploit Services ─────────────────────────────────────────────────────────

async def run_exploit_test_service(req: ExploitTestRequest, broadcast_cb) -> Dict[str, Any]:
    t_url = req.target_url or req.url
    if not t_url:
        raise HTTPException(status_code=400, detail="Missing target URL (target_url or url)")
        
    parsed = urlparse(t_url)
    clean_host = parsed.netloc or parsed.path
    if ":" in clean_host:
        clean_host = clean_host.split(":")[0]
    if not scope_manager.is_in_scope(clean_host):
        raise HTTPException(status_code=403, detail=f"Host '{clean_host}' is out of scope")

    from agents.exploit_tester import AutonomousExploiter
    
    exploiter = AutonomousExploiter(
        target_url=t_url,
        vuln_type=req.vuln_type or "general",
        base_payload=req.base_payload or "",
        vector=req.vector or "",
        broadcast_cb=broadcast_cb,
        post_action=req.post_action or "Verify Only",
        use_ai=bool(req.use_ai),
        surface_node=req.surface_node,
        auth_profile=req.auth_profile,
    )
    
    _set_active_exploiter(exploiter)
    
    try:
        result = await exploiter.run()
        result["execution_id"] = gen_id()
        _set_exploit_result(result)
        return result
    except Exception as e:
        logger.error("Exploit execution failed: %s", e, exc_info=True)
        return {"success": False, "error": str(e), "execution_id": gen_id()}

async def run_exploit_operator_action_service(req: ExploitActionRequest) -> Dict[str, Any]:
    exploit_result = _get_exploit_result()
    if not exploit_result:
        return {"error": "No active exploit result found."}

    handoff = exploit_result.get("operator_handoff") or {}
    actions = handoff.get("available_actions") or []
    
    action_meta = None
    for a in actions:
        if a.get("id") == req.action:
            action_meta = a
            break
            
    if not action_meta:
        return {"error": f"Action '{req.action}' not available."}

    if action_meta.get("requires_confirmation") and not req.confirm:
        return {"error": f"Confirmation is required for action '{req.action}'."}

    return {
        "status": "success",
        "action": req.action,
        "result": "Action executed successfully"
    }

async def stop_exploit_service(req: Optional[ExploitStopRequest] = None) -> Dict[str, Any]:
    active_exploiter = _get_active_exploiter()
    if active_exploiter:
        try:
            await active_exploiter.client.aclose()
        except Exception:
            pass
        try:
            await active_exploiter.oast_client.close()
        except Exception:
            pass
        _set_active_exploiter(None)
    return {"status": "stopped"}

# ─── OAST Services ────────────────────────────────────────────────────────────

async def get_oast_settings_service() -> Dict[str, Any]:
    return {"enabled": False, "domain": "", "poll_interval": 5}

async def update_oast_settings_service(payload: OASTSettingsUpdate) -> Dict[str, Any]:
    try:
        settings = update_oast_settings(payload.domain, payload.token, payload.provider)
        return settings
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

# ─── Hibernation Services ──────────────────────────────────────────────────────

async def request_hibernation_service(hibernate_signal_file: Any) -> Dict[str, Any]:
    hibernate_signal_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "action": "hibernate",
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "source": "sentinel-api",
    }
    tmp_file = hibernate_signal_file.with_suffix(".tmp")
    tmp_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp_file.replace(hibernate_signal_file)
    return {
        "status": "hibernate_requested",
        "message": "Bootloader signal written. The dashboard will disconnect during the AI batch.",
    }

# ─── Concurrent Fuzz Request Wrapper ──────────────────────────────────────────

async def run_pooled_fuzz_request(method: str, url: str, **kwargs) -> Any:
    """
    Executes an HTTP request using the centralized AsyncClient pool.
    Guards execution with the hard concurrency Semaphore (15) to prevent socket leaks.
    """
    client = await HTTPClientPool.get_client()
    async with fuzzer_semaphore:
        try:
            response = await client.request(method, url, **kwargs)
            return response
        except Exception as e:
            logger.error("Pooled request to %s failed: %s", url, e, exc_info=True)
            raise
