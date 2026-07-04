"""
Pipeline Manager — automated execution engine for scanning profiles.
Resolves tool binaries on PATH, formats commands, manages temporary file handoffs,
and streams execution status/output via TaskOrchestrator.
"""
import os
import json
import shutil
import logging
import asyncio
import glob
import re
from typing import Dict, Any, List
from datetime import datetime, timezone

from sqlalchemy import update
from core.database import AsyncSessionLocal
from core.models import Job, Target
from core.orchestrator import orchestrator
from core.parser import ingest_findings
from agents.active_scanner import run_active_scan

logger = logging.getLogger(__name__)

# Predefined scan profiles
PROFILES = {
    "Subdomain Recon": {
        "description": "Automatically discovers subdomains using subfinder",
        "steps": [
            {
                "tool": "subfinder",
                "binary": "subfinder",
                "command_tpl": "subfinder -d {host} -oJ",
                "output_format": "json"
            }
        ]
    },
    "Active Auditing": {
        "description": "Template-based active auditing using nuclei",
        "steps": [
            {
                "tool": "nuclei",
                "binary": "nuclei",
                "command_tpl": "nuclei -u {host} -json-export {out_file}",
                "output_format": "json",
                "use_temp_out": True
            }
        ]
    },
    "Active Vulnerability Scan": {
        "description": "Template-based active vulnerability scanning using nuclei",
        "steps": [
            {
                "tool": "nuclei",
                "binary": "nuclei",
                "command_tpl": "nuclei -u {host} -json-export {out_file}",
                "output_format": "json",
                "use_temp_out": True
            }
        ]
    },
    "Full Pipeline": {
        "description": "Chains Subdomain Recon with Active Auditing",
        "steps": [
            {
                "tool": "subfinder",
                "binary": "subfinder",
                "command_tpl": "subfinder -d {host} -o {temp_domains}",
                "output_format": "txt",
                "use_temp_domains": True
            },
            {
                "tool": "nuclei",
                "binary": "nuclei",
                "command_tpl": "nuclei -l {temp_domains} -json-export {out_file}",
                "output_format": "json",
                "use_temp_out": True
            }
        ]
    },
    "Inventory Mapping": {
        "description": "Enterprise Asset Inventory: discovers subdomains, indexes URLs, and validates health",
        "steps": [
            {
                "tool": "subfinder",
                "binary": "subfinder",
                "command_tpl": "subfinder -d {host} -o {temp_domains}",
                "output_format": "txt",
                "use_temp_domains": True
            },
            {
                "tool": "naabu",
                "binary": "naabu",
                "command_tpl": "naabu -list {temp_domains} -p 80,443,8000,8080,8081,8443,9000,9090 -rate 1000 -timeout 500 -c 50 -o {temp_ports}",
                "output_format": "txt",
                "use_temp_ports": True
            },
            {
                "tool": "katana",
                "binary": "katana",
                "command_tpl": "katana -list {temp_ports} -jc -j -o {temp_urls}",
                "output_format": "json",
                "use_temp_urls": True
            },
            {
                "tool": "nuclei",
                "binary": "nuclei",
                "command_tpl": "nuclei -l {temp_urls} -json-export {temp_health}",
                "output_format": "json",
                "use_temp_health": True
            }
        ]
    },
    "Deep Mapping": {
        "description": "Deep Analytical Mapping: discovers subdomains and performs passive URL crawling",
        "steps": [
            {
                "tool": "subfinder",
                "binary": "subfinder",
                "command_tpl": "subfinder -d {host} -o {temp_domains}",
                "output_format": "txt",
                "use_temp_domains": True
            },
            {
                "tool": "naabu",
                "binary": "naabu",
                "command_tpl": "naabu -list {temp_domains} -p 80,443,8000,8080,8081,8443,9000,9090 -rate 1000 -timeout 500 -c 50 -o {temp_ports}",
                "output_format": "txt",
                "use_temp_ports": True
            },
            {
                "tool": "katana",
                "binary": "katana",
                "command_tpl": "katana -list {temp_ports} -jc -j -o {temp_urls}",
                "output_format": "json",
                "use_temp_urls": True
            }
        ]
    },
    "APEX Engine": {
        "description": "Asymmetric AI-mutated vulnerability verification and targeted testing pipeline",
        "steps": [
            {
                "tool": "APEX Engine",
                "run_fn": "run_apex_pipeline"
            }
        ]
    },
    "Cognitive AI Recon": {
        "description": "Autonomous Cognitive Engine vulnerability verification pipeline",
        "steps": [
            {
                "tool": "Cognitive AI Recon",
                "run_fn": "run_cognitive_pipeline"
            }
        ]
    }
}


def verify_binary_exists(binary_name: str) -> bool:
    """Check if the binary exists in PATH."""
    return os.path.isfile(binary_name) or shutil.which(binary_name) is not None


def _version_key(path: str) -> tuple:
    parent = os.path.basename(os.path.dirname(path))
    return tuple(int(part) for part in re.findall(r"\d+", parent))


def resolve_binary(binary_name: str, binary_glob: str | None = None) -> str:
    if binary_glob:
        candidates = [path for path in glob.glob(binary_glob) if os.path.isfile(path)]
        if candidates:
            return sorted(candidates, key=_version_key, reverse=True)[0]
    resolved = shutil.which(binary_name)
    return resolved or binary_name


def _is_naabu_no_valid_targets_error(error_detail: str) -> bool:
    return "no valid ipv4 or ipv6 targets" in error_detail.lower()


def _spawn_background_discovery(coro):
    return asyncio.create_task(coro)


async def run_pipeline(job_id: str, profile_name: str, target_id: str):
    """Executes a profile pipeline step-by-step with status logging."""
    if profile_name not in PROFILES:
        err = f"Unknown profile: {profile_name}"
        await _fail_job(job_id, err)
        return

    # Fetch target details
    async with AsyncSessionLocal() as session:
        target = await session.get(Target, target_id)
        if not target:
            await _fail_job(job_id, f"Target {target_id} not found")
            return
        host = target.host
        tech_stack = [t.lower() for t in (target.tech_stack or [])]

    profile = PROFILES[profile_name]
    logger.info("Starting pipeline '%s' for target '%s'", profile_name, host)

    # Temporary directory for file chaining
    temp_dir = os.path.join(os.getcwd(), "scratch", f"job_{job_id}")
    os.makedirs(temp_dir, exist_ok=True)

    temp_domains_path = os.path.join(temp_dir, "discovered_domains.txt")
    temp_out_path = os.path.join(temp_dir, "nuclei_out.json")
    temp_urls_path = os.path.join(temp_dir, "katana_out.txt")
    temp_health_path = os.path.join(temp_dir, "nuclei_health.json")
    temp_ports_path = os.path.join(temp_dir, "naabu_ports.txt")

    # Update job state to running
    await orchestrator._update_job_status(job_id, "running", started_at=datetime.now(timezone.utc))
    await orchestrator._broadcast_msg({
        "type": "job_status",
        "job_id": job_id,
        "status": "running",
        "tool": profile_name
    })

    try:
        for idx, step in enumerate(profile["steps"]):
            tool = step["tool"]
            
            if "run_fn" in step:
                if step["run_fn"] == "run_apex_pipeline":
                    from core.apex_coordinator import run_apex_pipeline
                    async def stream_broadcast(msg):
                        await orchestrator._broadcast_msg(msg)
                    await run_apex_pipeline(target_id, job_id, stream_broadcast)
                    continue
                elif step["run_fn"] == "run_cognitive_pipeline":
                    from services.scanner import run_cognitive_pipeline
                    await run_cognitive_pipeline(job_id, target_id)
                    continue

            binary = resolve_binary(step["binary"], step.get("binary_glob"))

            # 1. Verify PATH requirements
            if not verify_binary_exists(binary):
                err_msg = f"Dependency '{binary}' not found in system PATH. Job aborted."
                await orchestrator._broadcast_msg({
                    "type": "terminal_output",
                    "job_id": job_id,
                    "stream": "stderr",
                    "line": f"[ERROR] {err_msg}",
                    "tool": tool
                })
                raise RuntimeError(err_msg)

            # 2. Build template command
            tpl = step["command_tpl"]
            fmt_kwargs = {
                "host": host,
                "binary": binary,
                "temp_domains": temp_domains_path,
                "out_file": temp_out_path,
                "temp_urls": temp_urls_path,
                "temp_health": temp_health_path,
                "temp_ports": temp_ports_path,
            }

            # Format the final command string
            cmd = tpl.format(**fmt_kwargs)

            # Apply Technology-Based Scan Filtering for nuclei
            if tool == "nuclei" and tech_stack:
                exclude_tags = []
                
                # Check for Java absence
                if not any("java" in t or "spring" in t or "tomcat" in t or "wildfly" in t for t in tech_stack):
                    exclude_tags.extend(["log4j", "spring", "actuator", "solr", "weblogic", "jenkins", "tomcat", "wildfly"])
                
                # Check for PHP absence
                if not any("php" in t or "wordpress" in t or "drupal" in t for t in tech_stack):
                    exclude_tags.extend(["php", "drupal", "wordpress", "joomla", "laravel", "thinkphp"])
                
                # Check for Python absence
                if not any("python" in t or "django" in t or "flask" in t for t in tech_stack):
                    exclude_tags.extend(["django", "flask", "python"])
                
                # Check for IIS/ASP.NET absence
                if not any("iis" in t or "asp.net" in t or "windows" in t or "c#" in t for t in tech_stack):
                    exclude_tags.extend(["iis", "aspnet", "exchange", "active-directory"])

                if exclude_tags:
                    cmd += f" -exclude-tags {','.join(sorted(list(set(exclude_tags))))}"

            # Log execution step
            await orchestrator._broadcast_msg({
                "type": "terminal_output",
                "job_id": job_id,
                "stream": "stdout",
                "line": f"[INFO] Running step {idx+1}/{len(profile['steps'])}: {cmd}",
                "tool": tool
            })

            # 3. Wait for system resource headroom before executing
            from core.resource_governor import system_healthy
            await system_healthy.wait()

            # 4. Execute step using TaskOrchestrator
            res = await orchestrator.execute_job(job_id, cmd, tool)

            # If the step failed, abort the pipeline
            if res["status"] != "completed":
                error_detail = res.get("error") or res.get("stderr") or "unknown"
                if step.get("use_temp_ports") and _is_naabu_no_valid_targets_error(error_detail):
                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stderr",
                        "line": "[WARN] Port scanner could not resolve valid IP targets. Defaulting to discovered subdomains for crawling.",
                        "tool": tool
                    })
                else:
                    raise RuntimeError(f"Step '{tool}' execution failed (exit code: {res.get('exit_code')}) — {error_detail}")

            # 4. Handle output ingestion or handoff
            if step.get("use_temp_domains"):
                # Check that domains were discovered
                if os.path.exists(temp_domains_path) and os.path.getsize(temp_domains_path) > 0:
                    with open(temp_domains_path, "r", encoding="utf-8") as f:
                        lines = [line.strip() for line in f if line.strip()]
                    
                    # Ingest discovered subdomains
                    subdomain_findings = []
                    async with AsyncSessionLocal() as session:
                        from core.diff_engine import process_discovered_subdomain_diff
                        for sub in lines:
                            await process_discovered_subdomain_diff(session, target_id, sub, "subfinder")
                            if sub != host:
                                subdomain_findings.append({
                                    "subdomain": sub,
                                    "host": host
                                })
                    if subdomain_findings:
                        json_str = json.dumps(subdomain_findings)
                        new_count = await ingest_findings(target_id, job_id, json_str, "json")
                        await orchestrator._broadcast_msg({
                            "type": "terminal_output",
                            "job_id": job_id,
                            "stream": "stdout",
                            "line": f"[INFO] Ingested {new_count} new subdomains from recon step.",
                            "tool": tool
                        })
                    
                    # Trigger background SAN extraction and Wayback Machine CDX API fetch
                    async def run_bg_discovery(target_id: str, host: str, discovered_subs: List[str]):
                        all_hosts = list(set([host] + discovered_subs))
                        sem_bg = asyncio.Semaphore(3)
                        
                        async def extract_and_save_sans(h: str):
                            async with sem_bg:
                                try:
                                    from core.ssl_extractor import extract_sans
                                    loop = asyncio.get_running_loop()
                                    sans = await loop.run_in_executor(None, extract_sans, h, 443)
                                    if sans:
                                        async with AsyncSessionLocal() as session:
                                            from core.diff_engine import process_discovered_subdomain_diff
                                            for san in sans:
                                                if san.endswith(host):
                                                    await process_discovered_subdomain_diff(session, target_id, san, "san")
                                except Exception as e:
                                    logger.debug("Background SAN extraction failed for %s: %s", h, e)
                        
                        async def fetch_and_save_wayback():
                            try:
                                from core.osint_fetcher import fetch_wayback_subdomains
                                wayback_subs = await fetch_wayback_subdomains(host)
                                if wayback_subs:
                                    async with AsyncSessionLocal() as session:
                                        from core.diff_engine import process_discovered_subdomain_diff
                                        for wsub in wayback_subs:
                                            await process_discovered_subdomain_diff(session, target_id, wsub, "wayback")
                            except Exception as e:
                                logger.debug("Background Wayback fetch failed: %s", e)

                        tasks = [asyncio.create_task(extract_and_save_sans(h)) for h in all_hosts]
                        tasks.append(asyncio.create_task(fetch_and_save_wayback()))
                        await asyncio.gather(*tasks, return_exceptions=True)
                        
                        from core.scoring import update_target_scores
                        await update_target_scores(target_id)
                    
                    _spawn_background_discovery(run_bg_discovery(target_id, host, lines))
                else:
                    # Write target host to domains file as fallback so Nuclei doesn't fail
                    with open(temp_domains_path, "w", encoding="utf-8") as f:
                        f.write(host + "\n")
                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stdout",
                        "line": f"[INFO] No subdomains found. Defaulting to base target: {host}",
                        "tool": tool
                    })

            elif step.get("use_temp_ports"):
                # Port scan output handler
                if os.path.exists(temp_ports_path) and os.path.getsize(temp_ports_path) > 0:
                    with open(temp_ports_path, "r", encoding="utf-8") as f:
                        lines = [line.strip() for line in f if line.strip()]
                    
                    # Ingest discovered ports/subdomains into discovered_subdomains table
                    async with AsyncSessionLocal() as session:
                        from core.diff_engine import process_discovered_subdomain_diff
                        for port_target in lines:
                            await process_discovered_subdomain_diff(session, target_id, port_target, "naabu")
                    
                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stdout",
                        "line": f"[INFO] Port scan completed. Ingested {len(lines)} active targets.",
                        "tool": tool
                    })
                else:
                    # Fallback: copy temp_domains to temp_ports
                    if os.path.exists(temp_domains_path) and os.path.getsize(temp_domains_path) > 0:
                        shutil.copy(temp_domains_path, temp_ports_path)
                    else:
                        with open(temp_ports_path, "w", encoding="utf-8") as f:
                            f.write(host + "\n")
                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stdout",
                        "line": f"[INFO] Port scanner returned no open ports. Defaulting to discovered subdomains.",
                        "tool": tool
                    })

            elif step.get("use_temp_out"):
                # Read Nuclei JSON file findings and ingest them
                if os.path.exists(temp_out_path):
                    with open(temp_out_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read().strip()
                    
                    parsed_findings = []
                    if content:
                        try:
                            # Try parsing the whole content as JSON (e.g. if it's a JSON array or single dict)
                            data = json.loads(content)
                            if isinstance(data, list):
                                for item in data:
                                    if isinstance(item, dict):
                                        parsed_findings.append(json.dumps(item))
                                    elif isinstance(item, list):
                                        for sub_item in item:
                                            if isinstance(sub_item, dict):
                                                parsed_findings.append(json.dumps(sub_item))
                            elif isinstance(data, dict):
                                parsed_findings.append(json.dumps(data))
                        except json.JSONDecodeError:
                            # Fallback: Parse line-by-line (JSON Lines format)
                            for line in content.splitlines():
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    item = json.loads(line)
                                    if isinstance(item, list):
                                        for sub_item in item:
                                            if isinstance(sub_item, dict):
                                                parsed_findings.append(json.dumps(sub_item))
                                    elif isinstance(item, dict):
                                        parsed_findings.append(json.dumps(item))
                                except json.JSONDecodeError:
                                    continue

                    if parsed_findings:
                        # Build mock JSON array structure
                        json_str = "[" + ",".join(parsed_findings) + "]"
                        new_count = await ingest_findings(target_id, job_id, json_str, "json")
                    else:
                        new_count = 0

                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stdout",
                        "line": f"[INFO] Ingested {new_count} new findings from active audit.",
                        "tool": tool
                    })
            elif step.get("use_temp_urls"):
                # Katana outputs JSON Lines to temp_urls_path. Process them.
                if os.path.exists(temp_urls_path):
                    with open(temp_urls_path, "r", encoding="utf-8", errors="replace") as f:
                        urls_content = f.read()
                    
                    from core.url_parser import ingest_katana_urls
                    new_urls_count = await ingest_katana_urls(target_id, job_id, urls_content)
                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stdout",
                        "line": f"[INFO] Ingested {new_urls_count} new endpoints from URL crawler.",
                        "tool": tool
                    })
                else:
                    # If Katana didn't run or output nothing, default to the subdomains file if exists, or host
                    fallback_urls = []
                    if os.path.exists(temp_domains_path):
                        with open(temp_domains_path, "r", encoding="utf-8") as f:
                            for d in f:
                                d = d.strip()
                                if d:
                                    fallback_urls.append(f"http://{d}")
                                    fallback_urls.append(f"https://{d}")
                    else:
                        fallback_urls = [f"http://{host}", f"https://{host}"]
                    
                    with open(temp_urls_path, "w", encoding="utf-8") as f:
                        for u in fallback_urls:
                            f.write(u + "\n")
                    
                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stdout",
                        "line": f"[INFO] No crawled URLs found. Defaulting to subdomains / host for health check.",
                        "tool": tool
                    })

            elif step.get("use_temp_health"):
                # Nuclei health checks outputs JSON Lines to temp_health_path.
                # It evaluates vulnerability/health on crawled URLs.
                # Update status code and has_alert flag for matched URLs.
                if os.path.exists(temp_health_path):
                    from sqlalchemy import update
                    from core.models import CrawledURL
                    
                    # Parse Nuclei JSON Lines output
                    with open(temp_health_path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                h_data = json.loads(line)
                                matched_url = h_data.get("matched-url") or h_data.get("matched")
                                if matched_url:
                                    # Nuclei output contains finding alerts.
                                    # Set has_alert = True if there's any alert finding.
                                    # Let's also check severity. If severity is high/critical/medium/low, set has_alert to True.
                                    severity = h_data.get("info", {}).get("severity") or h_data.get("severity") or "info"
                                    has_alert = severity.lower() in ("critical", "high", "medium", "low")
                                    
                                    async with AsyncSessionLocal() as session:
                                        await session.execute(
                                            update(CrawledURL)
                                            .where(
                                                CrawledURL.target_id == target_id,
                                                CrawledURL.url == matched_url
                                            )
                                            .values(
                                                has_alert=has_alert,
                                                status_code=h_data.get("status-code") or 200 # default to 200 if matched but no code
                                            )
                                        )
                                        await session.commit()
                            except Exception as parse_ex:
                                logger.error("Failed to parse nuclei health finding: %s", parse_ex)
                                
                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stdout",
                        "line": f"[INFO] Completed health validation step.",
                        "tool": tool
                    })

            elif step.get("output_format") == "json":
                # Ingest findings from command stdout
                stdout_str = res.get("stdout", "")
                if stdout_str.strip():
                    new_count = await ingest_findings(target_id, job_id, stdout_str, "json")
                    await orchestrator._broadcast_msg({
                        "type": "terminal_output",
                        "job_id": job_id,
                        "stream": "stdout",
                        "line": f"[INFO] Ingested {new_count} new findings from tool stdout.",
                        "tool": tool
                    })

        # Pipeline finished successfully
        await orchestrator._update_job_status(job_id, "completed", completed_at=datetime.now(timezone.utc))
        await orchestrator._broadcast_msg({
            "type": "job_status",
            "job_id": job_id,
            "status": "completed",
            "tool": profile_name
        })

    except Exception as e:
        logger.error("Pipeline '%s' failed: %s", profile_name, e)
        await _fail_job(job_id, str(e))
    finally:
        # Cleanup temporary files and directory
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
        except Exception as e:
            logger.error("Failed to clean up temporary directory %s: %s", temp_dir, e)


async def _fail_job(job_id: str, error_msg: str):
    await orchestrator._update_job_status(
        job_id, "failed",
        stderr=error_msg,
        completed_at=datetime.now(timezone.utc)
    )
    await orchestrator._broadcast_msg({
        "type": "job_status",
        "job_id": job_id,
        "status": "failed",
        "error": error_msg,
        "tool": "pipeline"
    })
    await orchestrator._broadcast_msg({
        "type": "terminal_output",
        "job_id": job_id,
        "stream": "stderr",
        "line": f"[FATAL] Pipeline error: {error_msg}",
        "tool": "pipeline"
    })
