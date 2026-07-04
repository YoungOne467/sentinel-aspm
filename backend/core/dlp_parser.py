import httpx
import re
import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import CrawledURL, DLPFinding, DiscoveredParameter, Target, ShadowAPI
from core.cve_mapper import map_cves_for_tech_stack
from core.oob_tracker import generate_canary_payload
from core.secret_extractor import analyze_static_asset_for_secrets

logger = logging.getLogger("sentinel.dlp_parser")

# Cap concurrency to 3
sem = asyncio.Semaphore(3)

# Regex compiled rules
SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_REGEX = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
TOKEN_REGEX = re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{16,}['\"]")
QUERY_PARAM_REGEX = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{1,64})\s*=")
SENSITIVE_IDENTIFIER_REGEX = re.compile(
    r"(?<![A-Za-z0-9_$])([A-Za-z_][A-Za-z0-9_]*(?:id|role|debug|admin|token|key|secret|tenant|account|user)[A-Za-z0-9_]*)(?![A-Za-z0-9_$])",
    re.IGNORECASE,
)
STRING_LITERAL_REGEX = re.compile(r"['\"`]([^'\"`]{2,96})['\"`]")

# Regex for relative REST API routes
ROUTE_REGEX = re.compile(
    r'(?:["\'`])'
    r'('
    r'/api/v\d+/[a-zA-Z0-9_\-\./]*|'
    r'/api/[a-zA-Z0-9_\-\./]+|'
    r'/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-\./]+'
    r')'
    r'(?:["\'`])'
)

def is_api_route(path: str) -> bool:
    lower_path = path.lower()
    # Exclude common static assets
    if any(lower_path.endswith(ext) for ext in [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", 
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".html", ".htm", ".json"
    ]):
        return False
    # Ensure it has at least one path separator if not starting with /api
    if path.count("/") < 2 and not path.startswith("/api"):
        return False
    return True


def _context_for_match(text: str, start: int, end: int, radius: int = 60) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].replace("\n", " ").strip()


def extract_js_parameters(body_text: str) -> list[dict]:
    """
    Extract developer-exposed parameters from JavaScript bundles.
    Returns dicts shaped for DiscoveredParameter persistence.
    """
    if not body_text:
        return []

    discovered: dict[tuple[str, str], dict] = {}

    for match in QUERY_PARAM_REGEX.finditer(body_text):
        name = match.group(1)
        discovered[(name, "query_string")] = {
            "name": name,
            "source": "query_string",
            "context": _context_for_match(body_text, match.start(), match.end()),
            "confidence": 0.95,
        }

    for match in STRING_LITERAL_REGEX.finditer(body_text):
        literal = match.group(1)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\-]{2,64}", literal) and re.search(
            r"(id|role|debug|admin|token|key|secret|tenant|account|user)",
            literal,
            re.IGNORECASE,
        ):
            discovered[(literal, "literal")] = {
                "name": literal,
                "source": "literal",
                "context": _context_for_match(body_text, match.start(), match.end()),
                "confidence": 0.75,
            }

    for match in SENSITIVE_IDENTIFIER_REGEX.finditer(body_text):
        name = match.group(1)
        discovered[(name, "identifier")] = {
            "name": name,
            "source": "identifier",
            "context": _context_for_match(body_text, match.start(), match.end()),
            "confidence": 0.7,
        }

    return list(discovered.values())[:200]

async def analyze_url_telemetry(crawled_url_id: str, url: str, target_id: str):
    """
    Fetches URL content (up to cap=3 concurrency), detects tech stack, performs DLP scans,
    and recalculates risk scores.
    """
    async with sem:
        try:
            logger.info("Starting telemetry analysis for URL: %s", url)
            
            # Use a stealth user agent and short timeout
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            }
            for oob_header in ("X-Forwarded-For", "X-Real-IP", "Referer", "Contact"):
                headers[oob_header] = await generate_canary_payload(
                    url,
                    oob_header,
                    target_id=target_id,
                    crawled_url_id=crawled_url_id,
                )
            
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(url, headers=headers)
                
                # Stack detection
                techs = set()
                server_hdr = resp.headers.get("Server", "")
                powered_by = resp.headers.get("X-Powered-By", "")
                
                for hdr_val in [server_hdr, powered_by]:
                    hdr_val_lower = hdr_val.lower()
                    if "nginx" in hdr_val_lower:
                        techs.add("nginx")
                    if "apache" in hdr_val_lower:
                        techs.add("Apache")
                    if "tomcat" in hdr_val_lower:
                        techs.add("Tomcat")
                    if "iis" in hdr_val_lower:
                        techs.add("IIS")
                    if "php" in hdr_val_lower:
                        techs.add("PHP")
                    if "asp.net" in hdr_val_lower:
                        techs.add("ASP.NET")
                
                body_text = resp.text
                body_lower = body_text.lower()
                
                if "_reactrootcontainer" in body_lower or "react-target" in body_lower or "__react_devtools_global_hook__" in body_lower or "react.production.min.js" in body_lower:
                    techs.add("React")
                if "ng-version" in body_lower or "ng-app" in body_lower:
                    techs.add("Angular")
                if "v-bind" in body_lower or "v-model" in body_lower or "__vue__" in body_lower:
                    techs.add("Vue")
                if "jquery" in body_lower or "jquery.min.js" in body_lower:
                    techs.add("jQuery")
                if "wp-content" in body_lower or "wp-includes" in body_lower:
                    techs.add("WordPress")
                if "bootstrap" in body_lower:
                    techs.add("Bootstrap")
                
                tech_list = list(techs)
                
                # Check if URL is static content for DLP scanning
                content_type = resp.headers.get("Content-Type", "").lower()
                is_static = (
                    any(ext in url.lower() for ext in [".js", ".json", ".txt", ".html", ".xml", ".config", ".env", ".yaml", ".yml"])
                    or "text/" in content_type
                    or "javascript" in content_type
                    or "json" in content_type
                )
                is_js = ".js" in url.lower() or "javascript" in content_type
                
                findings = []
                if is_static and body_text:
                    if is_js or "json" in content_type or url.lower().endswith(".json"):
                        await analyze_static_asset_for_secrets(
                            body_text,
                            url,
                            target_id=target_id,
                            crawled_url_id=crawled_url_id,
                        )

                    # Run regex rules
                    for match in SSN_REGEX.finditer(body_text):
                        val = match.group(0)
                        start = max(0, match.start() - 20)
                        end = min(len(body_text), match.end() + 20)
                        ctx = body_text[start:end].replace("\n", " ").strip()
                        findings.append({
                            "type": "PII",
                            "value": val,
                            "context": f"...{ctx}...",
                            "compliance": ["GDPR"]
                        })
                    
                    for match in EMAIL_REGEX.finditer(body_text):
                        val = match.group(0)
                        start = max(0, match.start() - 20)
                        end = min(len(body_text), match.end() + 20)
                        ctx = body_text[start:end].replace("\n", " ").strip()
                        findings.append({
                            "type": "PII",
                            "value": val,
                            "context": f"...{ctx}...",
                            "compliance": ["GDPR"]
                        })
                        
                    for match in PRIVATE_KEY_REGEX.finditer(body_text):
                        val = match.group(0)
                        start = max(0, match.start() - 20)
                        end = min(len(body_text), match.end() + 20)
                        ctx = body_text[start:end].replace("\n", " ").strip()
                        findings.append({
                            "type": "Credential",
                            "value": val,
                            "context": f"...{ctx}...",
                            "compliance": ["PCI-DSS"]
                        })
                        
                    for match in TOKEN_REGEX.finditer(body_text):
                        val = match.group(0)
                        start = max(0, match.start() - 20)
                        end = min(len(body_text), match.end() + 20)
                        ctx = body_text[start:end].replace("\n", " ").strip()
                        findings.append({
                            "type": "Credential",
                            "value": val,
                            "context": f"...{ctx}...",
                            "compliance": ["PCI-DSS"]
                        })

                # Limit findings per page to avoid memory overhead
                findings = findings[:30]

                # Extract relative routes from JS bundle
                extracted_routes = set()
                extracted_parameters = []
                if is_js and body_text:
                    for match in ROUTE_REGEX.finditer(body_text):
                        route_path = match.group(1)
                        if is_api_route(route_path):
                            extracted_routes.add(route_path)
                    extracted_parameters = extract_js_parameters(body_text)

                # Update database records
                async with AsyncSessionLocal() as session:
                    crawled_url = await session.get(CrawledURL, crawled_url_id)
                    if crawled_url:
                        crawled_url.tech_stack = tech_list
                        crawled_url.status_code = resp.status_code
                        crawled_url.known_cves = map_cves_for_tech_stack(tech_list)
                        
                        for f in findings:
                            db_f = DLPFinding(
                                crawled_url_id=crawled_url_id,
                                finding_type=f["type"],
                                value=f["value"],
                                context=f["context"],
                                compliance_tags=f["compliance"]
                            )
                            session.add(db_f)
                        
                        # Store shadow API routes
                        if extracted_routes:
                            existing_routes_query = await session.execute(
                                select(ShadowAPI.route).where(ShadowAPI.crawled_url_id == crawled_url_id)
                            )
                            existing_routes = set(existing_routes_query.scalars().all())
                            
                            for route in list(extracted_routes)[:100]:
                                if route not in existing_routes:
                                    db_route = ShadowAPI(
                                        crawled_url_id=crawled_url_id,
                                        route=route
                                    ) 
                                    session.add(db_route)

                        if extracted_parameters:
                            existing_params_query = await session.execute(
                                select(DiscoveredParameter.name, DiscoveredParameter.source).where(
                                    DiscoveredParameter.crawled_url_id == crawled_url_id
                                )
                            )
                            existing_params = set(existing_params_query.all())

                            for param in extracted_parameters:
                                key = (param["name"], param["source"])
                                if key not in existing_params:
                                    session.add(
                                        DiscoveredParameter(
                                            crawled_url_id=crawled_url_id,
                                            name=param["name"],
                                            source=param["source"],
                                            context=param["context"],
                                            confidence=param["confidence"],
                                        )
                                    )
                        
                        await session.commit()
                        
                    target = await session.get(Target, target_id)
                    if target:
                        current_tech = set(target.tech_stack or [])
                        current_tech.update(tech_list)
                        target.tech_stack = list(current_tech)
                        target.known_cves = map_cves_for_tech_stack(target.tech_stack)
                        await session.commit()
            
            # Recalculate target scores
            from core.scoring import update_target_scores
            await update_target_scores(target_id)
            logger.info("Completed telemetry analysis for URL: %s", url)
            
        except Exception as ex:
            logger.debug("Telemetry collection failed for URL %s: %s", url, ex)
            try:
                async with AsyncSessionLocal() as session:
                    crawled_url = await session.get(CrawledURL, crawled_url_id)
                    if crawled_url and crawled_url.status_code is None:
                        crawled_url.status_code = 0  # 0 indicates connection error
                        await session.commit()
            except Exception:
                pass
