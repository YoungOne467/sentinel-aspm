"""
Data Pipeline — JSON/XML parsing, normalization, deduplication, and ingestion.
Supports: generic JSON, generic XML, nmap XML, and auto-detection.
"""
import hashlib
import asyncio
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Dict, Any

from sqlalchemy import select

from core.database import AsyncSessionLocal, batch_writer
from core.models import Finding, gen_id

logger = logging.getLogger(__name__)


def compute_finding_hash(target_id: str, title: str, category: str, evidence: str) -> str:
    """Generate a SHA-256 hash for deduplication."""
    raw = f"{target_id}:{title}:{category}:{evidence}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ─── JSON Parser ───────────────────────────────────────────────────────────────

def parse_json_output(raw: str) -> List[Dict[str, Any]]:
    """Parse raw JSON output into normalized finding dicts."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        # Fallback: try parsing as JSON Lines (one JSON object per line)
        findings = []
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        for line in lines:
            try:
                item = json.loads(line)
                if isinstance(item, list):
                    for sub_item in item:
                        if isinstance(sub_item, dict):
                            findings.append(_normalize_finding(sub_item))
                        elif sub_item is not None:
                            findings.append(_normalize_finding(sub_item))
                elif isinstance(item, dict):
                    findings.append(_normalize_finding(item))
                elif item is not None:
                    findings.append(_normalize_finding(item))
            except json.JSONDecodeError:
                continue
        if findings:
            return findings
        logger.error("JSON parse error: %s", e)
        return []

    findings = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                findings.append(_normalize_finding(item))
            elif isinstance(item, list):
                for sub_item in item:
                    if isinstance(sub_item, dict):
                        findings.append(_normalize_finding(sub_item))
                    elif sub_item is not None:
                        findings.append(_normalize_finding(sub_item))
            elif item is not None:
                findings.append(_normalize_finding(item))
    elif isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "issues", "alerts", "matches"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, dict):
                        findings.append(_normalize_finding(item))
                    elif isinstance(item, list):
                        for sub_item in item:
                            if isinstance(sub_item, dict):
                                findings.append(_normalize_finding(sub_item))
                            elif sub_item is not None:
                                findings.append(_normalize_finding(sub_item))
                    elif item is not None:
                        findings.append(_normalize_finding(item))
                return findings
        findings.append(_normalize_finding(data))
    return findings


# ─── XML Parser ────────────────────────────────────────────────────────────────

def parse_xml_output(raw: str) -> List[Dict[str, Any]]:
    """Parse raw XML output into normalized finding dicts."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        logger.error("XML parse error: %s", e)
        return []

    if root.tag == "nmaprun":
        return _parse_nmap_xml(root)

    findings = []
    for tag in ("finding", "vulnerability", "issue", "alert", "result", "item", "entry"):
        for elem in root.iter(tag):
            findings.append(_normalize_xml_element(elem))
    return findings


def _parse_nmap_xml(root: ET.Element) -> List[Dict[str, Any]]:
    """Nmap-specific XML parser."""
    findings = []
    for host in root.findall(".//host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

        for port in host.findall(".//port"):
            pid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            state_el = port.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            svc_el = port.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            svc_prod = svc_el.get("product", "") if svc_el is not None else ""
            svc_ver = svc_el.get("version", "") if svc_el is not None else ""

            findings.append({
                "title": f"Open Port {pid}/{proto} — {svc_name}".strip(),
                "severity": "info",
                "category": "port_scan",
                "description": f"Port {pid}/{proto} is {state} on {addr}. "
                               f"Service: {svc_prod} {svc_ver}".strip(),
                "evidence": f"{addr}:{pid} ({state}) {svc_name} {svc_prod} {svc_ver}".strip(),
                "raw_data": {
                    "host": addr, "port": pid, "protocol": proto,
                    "state": state, "service": svc_name,
                    "product": svc_prod, "version": svc_ver,
                },
            })

        for script in host.findall(".//script"):
            sid = script.get("id", "")
            sout = script.get("output", "")
            sev = "high" if "vuln" in sid.lower() else "medium"
            findings.append({
                "title": f"Script: {sid}",
                "severity": sev,
                "category": "nmap_script",
                "description": sout[:500],
                "evidence": sout,
                "raw_data": {"script_id": sid, "output": sout},
            })

    return findings


# ─── Normalizers ───────────────────────────────────────────────────────────────

_SEVERITY_MAP = {
    "critical": "critical", "crit": "critical", "5": "critical", "urgent": "critical",
    "high": "high", "4": "high", "important": "high",
    "medium": "medium", "med": "medium", "3": "medium", "moderate": "medium", "warning": "medium",
    "low": "low", "2": "low", "minor": "low",
    "info": "info", "informational": "info", "1": "info", "0": "info", "none": "info",
}


def _normalize_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw.lower().strip(), "info")


def _normalize_finding(item: Dict[str, Any]) -> Dict[str, Any]:
    """Map arbitrary finding dict keys to standard schema."""
    if not isinstance(item, dict):
        return {
            "title": "Raw Finding Data",
            "severity": "info",
            "category": "general",
            "description": str(item),
            "evidence": str(item),
            "solution": "",
            "raw_data": {"raw": item} if not isinstance(item, (dict, list)) else {"raw_list": item},
        }

    if "subdomain" in item:
        sub = item.get("subdomain") or ""
        return {
            "title": f"Discovered Subdomain: {sub}",
            "severity": "info",
            "category": "subdomain_recon",
            "description": f"Discovered subdomain {sub} during recon scan.",
            "evidence": f"Subdomain: {sub}\nHost: {item.get('host', '')}",
            "solution": "",
            "raw_data": item,
        }
    elif "host" in item and "source" in item:
        sub = item.get("host") or ""
        return {
            "title": f"Discovered Subdomain: {sub}",
            "severity": "info",
            "category": "subdomain_recon",
            "description": f"Discovered subdomain {sub} during recon scan.",
            "evidence": f"Subdomain: {sub}\nSource: {item.get('source', '')}",
            "solution": "",
            "raw_data": item,
        }

    title = (item.get("title") or item.get("name") or item.get("summary")
             or item.get("vulnerability") or item.get("alert") or "Untitled Finding")
    severity_raw = str(item.get("severity") or item.get("risk")
                       or item.get("level") or item.get("priority") or "info")
    severity = _normalize_severity(severity_raw)
    category = (item.get("category") or item.get("type")
                or item.get("plugin_family") or item.get("class") or "general")
    description = (item.get("description") or item.get("desc")
                   or item.get("details") or item.get("message") or "")
    evidence = (item.get("evidence") or item.get("proof")
                or item.get("output") or item.get("data") or "")
    if isinstance(evidence, (dict, list)):
        evidence = json.dumps(evidence)
    solution = (item.get("solution") or item.get("remediation")
                or item.get("fix") or item.get("recommendation") or "")

    return {
        "title": str(title)[:500],
        "severity": severity,
        "category": str(category)[:100],
        "description": str(description)[:5000],
        "evidence": str(evidence)[:5000],
        "solution": str(solution)[:2000],
        "raw_data": item,
    }


def _normalize_xml_element(elem: ET.Element) -> Dict[str, Any]:
    data = {}
    for child in elem:
        data[child.tag] = child.text or ""
    data.update(elem.attrib)
    return _normalize_finding(data)


# ─── Ingestion Entrypoint ─────────────────────────────────────────────────────

async def ingest_findings(
    target_id: str,
    job_id: str | None,
    raw_output: str,
    output_format: str = "json",
) -> int:
    """Parse, deduplicate, and store findings via micro-batch writer. Returns new count."""
    if output_format == "xml":
        parsed = parse_xml_output(raw_output)
    else:
        parsed = parse_json_output(raw_output)

    if not parsed:
        return 0

    new_count = 0
    async with AsyncSessionLocal() as session:
        for f in parsed:
            fhash = compute_finding_hash(
                target_id, f["title"], f["category"], f.get("evidence", ""),
            )
            from core.diff_engine import process_subdomain_diff
            is_new = await process_subdomain_diff(session, target_id, job_id, f["title"], fhash)
            
            if not is_new:
                continue

            if f.get("category") == "subdomain_recon":
                subdomain = (
                    (f.get("raw_data") or {}).get("subdomain")
                    or (f.get("raw_data") or {}).get("host")
                    or f.get("title", "").replace("Discovered Subdomain:", "").strip()
                )
                if subdomain:
                    from core.takeover_profiler import profile_subdomain_takeover

                    asyncio.create_task(profile_subdomain_takeover(subdomain, target_id))

            new_finding = Finding(
                id=gen_id(),
                job_id=job_id,
                target_id=target_id,
                title=f["title"],
                severity=f["severity"],
                category=f["category"],
                description=f["description"],
                evidence=f.get("evidence", ""),
                solution=f.get("solution", ""),
                hash=fhash,
                raw_data=f.get("raw_data"),
                is_new=True,
            )
            await batch_writer.enqueue(new_finding)
            new_count += 1

    # Force flush remaining buffer
    await batch_writer.flush()
    return new_count
