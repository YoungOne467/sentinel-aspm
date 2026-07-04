"""
Active Scanner (DAST Engine) — Context-Aware Orchestration of All Attack Modules.

This is the brain of the active scanning pipeline. It:
1. Executes all 13 attack modules in a logical order.
2. Streams real-time progress via WebSocket broadcast.
3. Aggregates, deduplicates, and severity-sorts all findings.
4. Enriches every finding with evidence-backed verification metadata.

Module Coverage (based on OWASP WSTG, PortSwigger Academy, OSCP/PNPT):
- Security Header Audit (OWASP WSTG-CONF)
- Sensitive File Discovery (OWASP WSTG-CONF-04)
- TCP Port Scanning (network reconnaissance)
- API Fuzzing / IDOR / JWT (OWASP WSTG-ATHZ)
- Injection Testing: SQLi, XSS, SSTI, CMDi, NoSQLi (OWASP WSTG-INPV)
- HTTP Request Smuggling (PortSwigger research)
- SSRF with OAST verification (OWASP A10:2021)
- CSRF & Clickjacking (OWASP WSTG-SESS, WSTG-CLNT)
- Path Traversal & LFI (OWASP WSTG-ATHZ-01)
- Open Redirect & Host Header Injection (OWASP WSTG-CLNT-04)
- Authentication & Session Security (OWASP WSTG-ATHN, WSTG-SESS)
- Information Disclosure & Error Handling (OWASP WSTG-ERRH, WSTG-INFO)
- TLS/SSL & Cryptographic Analysis (OWASP WSTG-CRYP)
"""
import asyncio, importlib, inspect, logging, re, time
from core.crawler import run_crawler
from core.param_miner import run_param_miner
from tools.nuclei_runner import run_nuclei_scan
from tools.ffuf_runner import run_dir_fuzzer
from core.oast_listener import clear_interactions
from core.finding_contract import normalize_findings
from core.auth_profiles import sanitize_auth_profiles
from core.surface_graph import ScanSurfaceGraph
from core.threat_adaptation import build_adaptive_scan_summary, module_priority_delta

logger = logging.getLogger(__name__)


def _optional_scan(module_name: str, attr_name: str):
    try:
        module = importlib.import_module(module_name)
        return getattr(module, attr_name)
    except Exception as exc:
        reason = f"{exc.__class__.__name__}: {exc}"

        async def _missing_module(url, intensity, broadcast_cb, **_kwargs):
            await broadcast_cb({
                "type": "log",
                "message": f"    - {module_name}.{attr_name}: skipped ({reason})",
            })
            return []

        _missing_module.__name__ = attr_name
        return _missing_module


run_xss_engine = _optional_scan("modules.xss_engine", "run_xss_scan")
run_sqli_engine = _optional_scan("modules.sqli_engine", "run_sqli_scan")
run_ssrf_engine = _optional_scan("modules.ssrf_engine", "run_ssrf_scan")
run_idor_engine = _optional_scan("modules.idor_engine", "run_idor_scan")
run_misconfig_engine = _optional_scan("modules.misconfig_engine", "run_misconfig_scan")
run_injection_scan = _optional_scan("modules.injection", "run_injection_scan")
run_attack_surface_scan = _optional_scan("modules.attack_surface", "run_attack_surface_scan")
run_template_probe_scan = _optional_scan("modules.template_probe", "run_template_probe_scan")
run_api_resource_consumption_scan = _optional_scan("modules.api_resource_consumption", "run_api_resource_consumption_scan")
run_authorization_matrix_scan = _optional_scan("modules.authorization_matrix", "run_authorization_matrix_scan")
run_client_exposure_scan = _optional_scan("modules.client_exposure", "run_client_exposure_scan")
run_smuggling_scan = _optional_scan("modules.smuggling", "run_smuggling_scan")
run_ssrf_scan = _optional_scan("modules.ssrf_oast", "run_ssrf_scan")
run_api_fuzz = _optional_scan("modules.api_fuzzer", "run_api_fuzz")
run_header_audit = _optional_scan("modules.header_audit", "run_header_audit")
run_sensitive_files_scan = _optional_scan("modules.sensitive_files", "run_sensitive_files_scan")
run_port_scan = _optional_scan("modules.port_scanner", "run_port_scan")
run_csrf_clickjack_scan = _optional_scan("modules.csrf_clickjack", "run_csrf_clickjack_scan")
run_path_traversal_scan = _optional_scan("modules.path_traversal", "run_path_traversal_scan")
run_redirect_host_scan = _optional_scan("modules.redirect_host", "run_redirect_host_scan")
run_auth_session_scan = _optional_scan("modules.auth_session", "run_auth_session_scan")
run_info_disclosure_scan = _optional_scan("modules.info_disclosure", "run_info_disclosure_scan")
run_tls_crypto_scan = _optional_scan("modules.tls_crypto", "run_tls_crypto_scan")
run_graphql_scan = _optional_scan("modules.graphql_security", "run_graphql_scan")
run_xxe_scan = _optional_scan("modules.xxe_scanner", "run_xxe_scan")
run_proto_pollution_scan = _optional_scan("modules.proto_pollution", "run_proto_pollution_scan")
run_mass_assignment_scan = _optional_scan("modules.mass_assignment", "run_mass_assignment_scan")
run_cache_deception_scan = _optional_scan("modules.cache_deception", "run_cache_deception_scan")
run_deserialization_scan = _optional_scan("modules.deserialization", "run_deserialization_scan")
run_ssti_scan = _optional_scan("modules.ssti_scanner", "run_ssti_scan")
run_file_upload_scan = _optional_scan("modules.file_upload", "run_file_upload_scan")
run_oauth_scan = _optional_scan("modules.oauth_security", "run_oauth_scan")
run_cache_poisoning_scan = _optional_scan("modules.cache_poisoning", "run_cache_poisoning_scan")
run_race_conditions_scan = _optional_scan("modules.race_conditions", "run_race_conditions_scan")
run_dom_xss_scan = _optional_scan("modules.dom_xss", "run_dom_xss_scan")
run_nosql_scan = _optional_scan("modules.nosql_injection", "run_nosql_scan")
run_jwt_advanced_scan = _optional_scan("modules.jwt_advanced", "run_jwt_advanced_scan")
run_websocket_scan = _optional_scan("modules.websocket_security", "run_websocket_scan")
run_ssrf_chaining_scan = _optional_scan("modules.ssrf_chaining", "run_ssrf_chaining_scan")
run_business_logic_v2_scan = _optional_scan("modules.business_logic_v2", "run_business_logic_v2_scan")
run_cors_scan = _optional_scan("modules.cors_misconfig", "run_cors_scan")
run_hpp_scan = _optional_scan("modules.hpp_scanner", "run_hpp_scan")
run_ldap_xpath_scan = _optional_scan("modules.ldap_xpath", "run_ldap_xpath_scan")
run_csp_scan = _optional_scan("modules.csp_analyzer", "run_csp_scan")
run_cloud_metadata_scan = _optional_scan("modules.cloud_metadata", "run_cloud_metadata_scan")
run_cmdi_advanced_scan = _optional_scan("modules.cmdi_advanced", "run_cmdi_advanced_scan")
run_blind_sqli_time_scan = _optional_scan("modules.blind_sqli_time", "run_blind_sqli_time_scan")
run_lfi_rce_escalation_scan = _optional_scan("modules.lfi_rce_escalation", "run_lfi_rce_escalation_scan")
run_java_jndi_log4j_scan = _optional_scan("modules.java_jndi_log4j", "run_java_jndi_log4j_scan")
run_http2_smuggling_scan = _optional_scan("modules.http2_smuggling", "run_http2_smuggling_scan")
run_waf_bypass_scan = _optional_scan("modules.waf_bypass", "run_waf_bypass_scan")
run_second_order_vulns_scan = _optional_scan("modules.second_order_vulns", "run_second_order_vulns_scan")
run_graphql_batch_dos_scan = _optional_scan("modules.graphql_batch_dos", "run_graphql_batch_dos_scan")
run_cve_scanner_auto_scan = _optional_scan("modules.cve_scanner_auto", "run_cve_scanner_auto_scan")
run_subdomain_brute_scan = _optional_scan("modules.subdomain_brute", "run_subdomain_brute_scan")
run_ssi_esi_injection_scan = _optional_scan("modules.ssi_esi_injection", "run_ssi_esi_injection_scan")
run_http_desync_advanced_scan = _optional_scan("modules.http_desync_advanced", "run_http_desync_advanced_scan")
run_ssti_blind_scan = _optional_scan("modules.ssti_blind", "run_ssti_blind_scan")
run_web_dav_scan = _optional_scan("modules.web_dav_scanner", "run_web_dav_scan")
run_graphql_introspection_scan = _optional_scan("modules.graphql_introspection", "run_graphql_introspection_scan")
run_spring_actuator_scan = _optional_scan("modules.spring_actuator_leak", "run_spring_actuator_scan")
run_php_cgi_cve_scan = _optional_scan("modules.php_cgi_cve", "run_php_cgi_cve_scan")
run_aws_cognito_scan = _optional_scan("modules.aws_cognito_misconfig", "run_aws_cognito_scan")
run_ssti_oast_scan = _optional_scan("modules.ssti_oast", "run_ssti_oast_scan")
run_smb_relay_scan = _optional_scan("modules.smb_relay_web", "run_smb_relay_scan")
run_llm_prompt_injection_scan = _optional_scan("modules.llm_prompt_injection", "run_llm_prompt_injection_scan")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
TOTAL_MODULES = 61
EARLY_MODULE_PATTERNS = (
    "attack surface",
    "security header",
    "tls",
    "information disclosure",
    "sensitive file",
    "api endpoint",
    "authentication",
    "graphql security",
    "cors",
    "cache poisoning",
    "cache deception",
    "authorization matrix",
    "client exposure",
    "resource consumption",
)
DEEP_MODULE_PATTERNS = (
    "batching dos",
    "jndi",
    "spraying",
    "lfi to rce",
    "http/2",
    "waf bypass",
    "second-order",
    "subdomain",
    "web-to-smb",
)


def _deduplicate(findings):
    """Remove duplicate findings based on type + vector."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("type",""), f.get("vector",""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _module_key(name: str) -> str:
    compacted = re.sub(r"(?<=[a-zA-Z])/(?=\d)", "", name)
    key = re.sub(r"[^a-zA-Z0-9]+", "_", compacted.lower()).strip("_")
    return re.sub(r"_+", "_", key)


def _module_priority(name: str, intensity: str, adaptive_summary: dict | None = None) -> int:
    lowered = name.lower()
    priority = 50
    if any(pattern in lowered for pattern in EARLY_MODULE_PATTERNS):
        priority -= 20
    if any(pattern in lowered for pattern in DEEP_MODULE_PATTERNS):
        priority += 30
    if intensity == "extreme" and any(pattern in lowered for pattern in DEEP_MODULE_PATTERNS):
        priority -= 10
    priority += module_priority_delta(name, adaptive_summary)
    return max(priority, 0)


def _sort_by_severity(findings):
    """Sort findings by risk score first, then severity."""
    return sorted(
        findings,
        key=lambda f: (
            -int(f.get("risk_score") or 0),
            SEVERITY_ORDER.get(f.get("severity", "Info"), 99),
        ),
    )


def _enrich_findings(findings, target_url):
    """Ensure all findings have a unique ID and the shared real-work contract."""
    import uuid
    enriched = normalize_findings(findings, target_url)
    for f in enriched:
        if "id" not in f:
            f["id"] = str(uuid.uuid4())
    return enriched


async def _invoke_module(func, url, intensity, broadcast_cb, scan_kwargs):
    signature = inspect.signature(func)
    accepts_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values())
    kwargs = scan_kwargs if accepts_kwargs else {key: value for key, value in scan_kwargs.items() if key in signature.parameters}
    return await func(url, intensity, broadcast_cb, **kwargs)


async def _run_module(name, number, func, url, intensity, broadcast_cb, all_findings, module_results, skip_condition=False, **scan_kwargs):
    """Helper to run a module with consistent logging and error handling."""
    if skip_condition:
        await broadcast_cb({"type": "log", "message": f"━━━ [Module {number}/{TOTAL_MODULES}] {name} (SKIPPED — stealth mode) ━━━"})
        return
    
    # Wait for memory and CPU headroom before starting the module
    from core.resource_governor import system_healthy, get_status
    await system_healthy.wait()

    # Dynamic delay based on resource pressure
    gov = get_status()
    if gov.get("ram_percent", 0) > 75 or gov.get("cpu_percent", 0) > 80:
        # High load: add a pacing delay to mitigate memory pressure
        await asyncio.sleep(0.8)

    await broadcast_cb({"type": "log", "message": f"━━━ [Module {number}/{TOTAL_MODULES}] {name} ━━━"})
    try:
        findings = await _invoke_module(func, url, intensity, broadcast_cb, scan_kwargs)
        findings = normalize_findings(findings, url)
        module_key = _module_key(name)
        module_results[module_key] = findings
        all_findings.extend(findings)
        count = len(findings)
        if count > 0:
            await broadcast_cb({"type": "log", "message": f"    ▸ {name}: {count} finding{'s' if count != 1 else ''}"})
        else:
            await broadcast_cb({"type": "log", "message": f"    ✓ {name}: Clean"})
    except Exception as e:
        logger.error("%s failed: %s", name, e)
        await broadcast_cb({"type": "log", "message": f"    ✗ {name}: ERROR — {e}"})


async def run_active_scan(url: str, intensity: str, broadcast_cb, scan_config: dict | None = None) -> dict:
    """
    Execute the full DAST active scanning pipeline (46 modules).
    Returns a dict with categorised results.
    """
    start_time = time.monotonic()
    all_findings = []
    module_results = {}
    scan_config = scan_config or {}
    auth_profiles = sanitize_auth_profiles(scan_config.get("auth_profiles"), legacy_headers=scan_config.get("scan_headers"))
    surface_graph = ScanSurfaceGraph(url, scope=scan_config.get("scope"))
    scan_kwargs = {
        "surface_graph": surface_graph,
        "auth_profiles": auth_profiles,
        "scan_config": scan_config,
    }

    # Reset OAST interactions for this scan
    clear_interactions()

    await broadcast_cb({
        "type": "log",
        "message": f"━━━ DAST ENGINE: Starting Active Scan on {url} ━━━"
    })
    await broadcast_cb({
        "type": "log",
        "message": f"    Intensity: {intensity.upper()} | Modules: {TOTAL_MODULES} | "
                   f"Coverage: OWASP WSTG + PortSwigger + OSCP/PNPT"
    })

    is_stealth = intensity == "stealth"

    # Phase 1: Deep Attack Surface Discovery
    try:
        await run_crawler(url, intensity, surface_graph, broadcast_cb)
    except Exception as e:
        logger.error("Crawler failed: %s", e)

    try:
        await run_param_miner(url, intensity, surface_graph, broadcast_cb)
    except Exception as e:
        logger.error("Param Miner failed: %s", e)
    adaptive_summary = build_adaptive_scan_summary(surface_graph, all_findings, auth_profiles, intensity)
    if adaptive_summary.get("recommended_modules"):
        await broadcast_cb({
            "type": "log",
            "message": (
                "Adaptive Threat Planner: prioritized "
                + ", ".join(adaptive_summary["recommended_modules"])
                + f" across {len(adaptive_summary.get('top_surface_nodes', []))} hot surface node(s)."
            ),
        })
    
    # ── Intensity-Based Concurrency ──────────────────────────────
    concurrency_map = {
        "stealth": 1,
        "normal": 15,
        "aggressive": 25,
        "extreme": 50
    }
    max_workers = concurrency_map.get(intensity, 15)
    
    task_queue = asyncio.PriorityQueue()

    def _enqueue_module(*args, **kwargs):
        name = args[0] if args else ""
        number = args[1] if len(args) > 1 else 0
        module_kwargs = {**scan_kwargs, **kwargs}
        task_queue.put_nowait((_module_priority(name, intensity, adaptive_summary), number, args, module_kwargs))
        return None

    # ── Task Definitions (Continuous Execution Pool — ALL MODULES FORCED) ──────────────────
    all_tasks = [
        _enqueue_module("Security Misconfigurations", 2, run_misconfig_engine, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("TLS/SSL Cryptographic Analysis", 3, run_tls_crypto_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Information Disclosure", 4, run_info_disclosure_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("CSRF and Clickjacking", 5, run_csrf_clickjack_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Sensitive File Discovery", 6, run_sensitive_files_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("TCP Port Scanning", 7, run_port_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("API Endpoint Fuzzing", 8, run_api_fuzz, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Authentication and Session", 8, run_auth_session_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Insecure Direct Object Reference (IDOR)", 8, run_idor_engine, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("SQL Injection (SQLi)", 9, run_sqli_engine, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Cross-Site Scripting (XSS)", 10, run_xss_engine, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Nuclei Template Scanner", 11, run_nuclei_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Directory and File Fuzzing", 12, run_dir_fuzzer, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Path Traversal and LFI", 10, run_path_traversal_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Open Redirect and Host Header", 11, run_redirect_host_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("HTTP Request Smuggling", 12, run_smuggling_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Server-Side Request Forgery (SSRF)", 13, run_ssrf_engine, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("GraphQL Security", 14, run_graphql_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("XML External Entity (XXE)", 15, run_xxe_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Prototype Pollution", 16, run_proto_pollution_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Mass Assignment", 17, run_mass_assignment_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Web Cache Deception", 18, run_cache_deception_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Insecure Deserialization", 19, run_deserialization_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Server-Side Template Injection (SSTI)", 20, run_ssti_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Unsafe File Upload", 21, run_file_upload_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("OAuth 2.0 Security", 22, run_oauth_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Web Cache Poisoning", 23, run_cache_poisoning_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Race Conditions", 24, run_race_conditions_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("DOM-based XSS", 25, run_dom_xss_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Advanced NoSQL Injection", 26, run_nosql_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("JWT Advanced (KID/JKU)", 27, run_jwt_advanced_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Authorization Matrix", 59, run_authorization_matrix_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("API Resource Consumption", 60, run_api_resource_consumption_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Client Exposure", 61, run_client_exposure_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("WebSocket Security (CSWSH)", 28, run_websocket_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("SSRF Chaining (Internal RCE)", 29, run_ssrf_chaining_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Advanced Business Logic V2", 30, run_business_logic_v2_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("CORS Misconfigurations", 31, run_cors_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("HTTP Parameter Pollution", 32, run_hpp_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("LDAP and XPath Injection", 33, run_ldap_xpath_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("CSP Bypass Analysis", 34, run_csp_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Cloud Metadata SSRF", 35, run_cloud_metadata_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Advanced OAST Command Injection", 36, run_cmdi_advanced_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Deep Time-Based Blind SQLi", 37, run_blind_sqli_time_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("LFI to RCE Escalation", 38, run_lfi_rce_escalation_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("JNDI Log4Shell Spraying", 39, run_java_jndi_log4j_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("HTTP/2 Smuggling (H2.TE)", 40, run_http2_smuggling_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Automated WAF Bypass", 41, run_waf_bypass_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Second-Order Vulnerabilities", 42, run_second_order_vulns_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("GraphQL Batching DoS", 43, run_graphql_batch_dos_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Automated CVE Scanner", 44, run_cve_scanner_auto_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Subdomain Takeover", 45, run_subdomain_brute_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("SSI and ESI Injection", 46, run_ssi_esi_injection_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Advanced HTTP Desync (CL.0/TE.0)", 47, run_http_desync_advanced_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Blind SSTI", 48, run_ssti_blind_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("WebDAV Misconfigurations", 49, run_web_dav_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("GraphQL Introspection", 50, run_graphql_introspection_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Spring Boot Actuator", 51, run_spring_actuator_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("PHP-CGI Injection (CVE-2012/2024)", 52, run_php_cgi_cve_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("AWS Cognito Misconfigurations", 53, run_aws_cognito_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("OAST-Based SSTI", 54, run_ssti_oast_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Web-to-SMB Relay (SSRF)", 55, run_smb_relay_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("LLM Prompt Injection", 56, run_llm_prompt_injection_scan, url, intensity, broadcast_cb, all_findings, module_results),
        _enqueue_module("Template Exposure Probe", 58, run_template_probe_scan, url, intensity, broadcast_cb, all_findings, module_results)
    ]

    async def _worker():
        while True:
            try:
                _, _, args, kwargs = task_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            try:
                await _run_module(*args, **kwargs)
            except Exception as e:
                logger.error("Worker task error: %s", e)
            finally:
                task_queue.task_done()

    workers = [asyncio.create_task(_worker()) for _ in range(max_workers)]
    try:
        await asyncio.gather(*workers)
    finally:
        # Ensure all workers are cancelled if the main scanner task is aborted
        for w in workers:
            if not w.done():
                w.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

    # ── Post-Processing ───────────────────────────────────────────────
    elapsed = time.monotonic() - start_time
    all_findings = _deduplicate(all_findings)
    all_findings = _enrich_findings(all_findings, url)
    all_findings = _sort_by_severity(all_findings)

    # Count by severity
    counts = {}
    for f in all_findings:
        sev = f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1

    await broadcast_cb({
        "type": "log",
        "message": f"━━━ DAST ENGINE: Active Scan Complete ({elapsed:.1f}s) ━━━"
    })
    await broadcast_cb({
        "type": "log",
        "message": f"    Total Findings: {len(all_findings)} | "
                   f"Critical: {counts.get('Critical',0)} | "
                   f"High: {counts.get('High',0)} | "
                   f"Medium: {counts.get('Medium',0)} | "
                   f"Low: {counts.get('Low',0)}"
    })

    return {
        "findings": all_findings,
        "module_results": module_results,
        "surface_graph": surface_graph.to_dict(),
        "summary": {
            "total": len(all_findings),
            "by_severity": counts,
            "scan_duration_seconds": round(elapsed, 1),
            "modules_executed": len(module_results),
            "surface_nodes": surface_graph.to_dict()["node_count"],
            "adaptive_threat_summary": adaptive_summary,
        }
    }
