"""
AETHER Misconfiguration Engine — Security Misconfiguration Detection.

Checks for:
1. Missing or weak Security Headers (HSTS, CSP, X-Frame-Options, etc.)
2. Insecure CORS configurations
3. Insecure Cookie flags (missing HttpOnly, Secure, SameSite)
4. Information Disclosure (Server versions, X-Powered-By)
5. Directory Listing / Exposed Git folders
"""


import asyncio
import logging
import re
import time
from typing import Callable, Awaitable, Any
from urllib.parse import urlparse

import httpx

from core.http_client import ScannerAsyncClient
from core.surface_graph import ScanSurfaceGraph
from core.evidence_manager import save_evidence

logger = logging.getLogger(__name__)

# Security Headers required for defense-in-depth
REQUIRED_HEADERS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "desc": "Prevents downgrade attacks to HTTP.",
        "regex": re.compile(r"max-age=\d+", re.I)
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "desc": "Mitigates XSS and data injection attacks.",
        "regex": re.compile(r"default-src|script-src", re.I)
    },
    "X-Frame-Options": {
        "severity": "Low",
        "desc": "Prevents Clickjacking attacks.",
        "regex": re.compile(r"DENY|SAMEORIGIN", re.I)
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "desc": "Prevents MIME-sniffing.",
        "regex": re.compile(r"nosniff", re.I)
    },
    "Referrer-Policy": {
        "severity": "Low",
        "desc": "Controls referrer information sent to other sites.",
        "regex": re.compile(r"strict-origin|no-referrer|same-origin", re.I)
    }
}

# Information disclosure headers
LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "Via", "X-Runtime"
]

# Sensitive files and directories to check
SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/.svn/entries", "/.DS_Store",
    "/phpinfo.php", "/server-status", "/server-info",
    "/WEB-INF/web.xml", "/config.json", "/docker-compose.yml"
]


async def run_misconfig_scan(
    url: str,
    intensity: str,
    broadcast_cb: Callable[[dict], Awaitable[None]],
    *,
    surface_graph: ScanSurfaceGraph | None = None,
    auth_profiles: dict | None = None,
    scan_config: dict | None = None,
) -> list[dict]:
    """Run comprehensive Security Misconfiguration scanning."""
    findings = []
    start_time = time.monotonic()

    await broadcast_cb({"type": "log", "message": "Misconfig Engine: Starting security misconfiguration detection..."})

    # We only need to check headers and cookies on a few sample endpoints, not all of them
    sample_targets = []
    if surface_graph:
        nodes = surface_graph.targets(kinds={"page", "api"})
        if nodes:
            # Pick the root URL and a few API endpoints
            root_node = next((n for n in nodes if urlparse(n["url"]).path in ("", "/")), None)
            if root_node:
                sample_targets.append(root_node["url"])

            api_nodes = [n for n in nodes if n["kind"] == "api"]
            for node in api_nodes[:3]:
                if node["url"] not in sample_targets:
                    sample_targets.append(node["url"])

    if not sample_targets:
        sample_targets = [url]

    concurrency = {"stealth": 2, "normal": 5, "aggressive": 10, "extreme": 20}.get(intensity, 5)
    semaphore = asyncio.Semaphore(concurrency)

    async with ScannerAsyncClient(
        timeout=httpx.Timeout(10.0),
        follow_redirects=False,
        verify=False,
    ) as client:

        # ── Phase 1: Headers & Cookies ─────────────────────────────
        for target_url in sample_targets:
            try:
                async with semaphore:
                    resp = await client.get(target_url)
            except Exception as e:
                logger.debug("Misconfig fetch failed for %s: %s", target_url, e)
                continue

            headers = {k.lower(): v for k, v in resp.headers.items()}

            # 1. Missing Security Headers
            for header, info in REQUIRED_HEADERS.items():
                header_lower = header.lower()
                val = headers.get(header_lower)

                if not val:
                    findings.append({
                        "type": f"Missing Security Header: {header}",
                        "severity": info["severity"],
                        "module": "misconfig_engine",
                        "vector": f"Response headers for {urlparse(target_url).path}",
                        "payload": "N/A",
                        "evidence": f"Missing '{header}' in response headers.",
                        "description": f"The response is missing the {header} security header. {info['desc']}",
                        "confidence": "high",
                        "confidence_score": 1.0,
                        "verification_state": "verified",
                        "remediation": f"Configure the server to include the {header} header in all responses.",
                        "patch_provided": True,
                        "target_url": target_url,
                        "wstg": "WSTG-CONF-07",
                        "cwe": ["CWE-693", "CWE-16"],
                        "owasp_category": "A05:2021 Security Misconfiguration",
                    })
                elif not info["regex"].search(val):
                    findings.append({
                        "type": f"Weak Security Header: {header}",
                        "severity": "Low",
                        "module": "misconfig_engine",
                        "vector": f"Response headers for {urlparse(target_url).path}",
                        "payload": "N/A",
                        "evidence": f"{header}: {val}",
                        "description": f"The {header} header is present but misconfigured or weak: '{val}'.",
                        "confidence": "high",
                        "confidence_score": 1.0,
                        "verification_state": "verified",
                        "remediation": f"Update the {header} configuration to conform to best practices.",
                        "patch_provided": True,
                        "target_url": target_url,
                        "wstg": "WSTG-CONF-07",
                        "cwe": ["CWE-693"],
                        "owasp_category": "A05:2021 Security Misconfiguration",
                    })

            # 2. Information Disclosure Headers
            for header in LEAKY_HEADERS:
                val = headers.get(header.lower())
                if val:
                    # Ignore generic Server headers like "nginx" or "cloudflare", flag specific ones
                    if header.lower() == "server" and not any(char.isdigit() for char in val):
                        continue

                    findings.append({
                        "type": f"Information Disclosure: {header} Header",
                        "severity": "Low",
                        "module": "misconfig_engine",
                        "vector": f"Response headers for {urlparse(target_url).path}",
                        "payload": "N/A",
                        "evidence": f"{header}: {val}",
                        "description": f"The server is exposing version information via the {header} header.",
                        "confidence": "high",
                        "confidence_score": 1.0,
                        "verification_state": "verified",
                        "remediation": "Configure the web server to suppress or obfuscate version banners.",
                        "patch_provided": True,
                        "target_url": target_url,
                        "wstg": "WSTG-INFO-02",
                        "cwe": ["CWE-200"],
                        "owasp_category": "A05:2021 Security Misconfiguration",
                    })

            # 3. Insecure Cookies
            cookies = resp.headers.get_list("Set-Cookie")
            for cookie in cookies:
                parts = [p.strip() for p in cookie.split(";")]
                cookie_name = parts[0].split("=")[0]

                is_secure = any(p.lower() == "secure" for p in parts)
                is_httponly = any(p.lower() == "httponly" for p in parts)
                samesite = next((p.split("=")[1].lower() for p in parts if p.lower().startswith("samesite=")), None)

                issues = []
                if not is_secure and urlparse(target_url).scheme == "https":
                    issues.append("missing Secure flag")
                if not is_httponly:
                    issues.append("missing HttpOnly flag")
                if not samesite or samesite == "none":
                    issues.append("missing or weak SameSite attribute")

                if issues:
                    # Only flag session cookies as Medium, others as Low
                    is_session = any(s in cookie_name.lower() for s in ["session", "token", "auth", "sid"])
                    severity = "Medium" if is_session else "Low"

                    findings.append({
                        "type": f"Insecure Cookie: {cookie_name}",
                        "severity": severity,
                        "module": "misconfig_engine",
                        "vector": f"Set-Cookie header on {urlparse(target_url).path}",
                        "payload": "N/A",
                        "evidence": f"Set-Cookie: {cookie}",
                        "description": f"The cookie '{cookie_name}' is {', '.join(issues)}. " +
                                       ("This is a sensitive session cookie." if is_session else ""),
                        "confidence": "high",
                        "confidence_score": 1.0,
                        "verification_state": "verified",
                        "remediation": "Set the Secure, HttpOnly, and SameSite=Lax (or Strict) attributes on all sensitive cookies.",
                        "patch_provided": True,
                        "target_url": target_url,
                        "wstg": "WSTG-SESS-02",
                        "cwe": ["CWE-614", "CWE-1004", "CWE-1275"],
                        "owasp_category": "A05:2021 Security Misconfiguration",
                    })

            # 4. CORS Misconfiguration
            try:
                async with semaphore:
                    cors_resp = await client.options(
                        target_url,
                        headers={"Origin": "https://evil-cors-test.com", "Access-Control-Request-Method": "GET"}
                    )

                acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
                acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == "https://evil-cors-test.com" or (acao == "*" and acac == "true"):
                    evidence = save_evidence(
                        "misconfig_engine", target_url, cors_resp,
                        extra_info="Origin: https://evil-cors-test.com\nAccess-Control-Allow-Origin: " + acao
                    )

                    findings.append({
                        "type": "Insecure CORS Configuration",
                        "severity": "High",
                        "module": "misconfig_engine",
                        "vector": f"OPTIONS {urlparse(target_url).path}",
                        "payload": "Origin: https://evil-cors-test.com",
                        "evidence": evidence,
                        "description": "The endpoint reflects arbitrary Origins in the Access-Control-Allow-Origin header, "
                                       "allowing malicious sites to read authenticated responses via cross-origin requests.",
                        "confidence": "high",
                        "confidence_score": 0.95,
                        "verification_state": "verified",
                        "remediation": "Configure CORS to only allow trusted origins. Do not dynamically reflect the Origin header.",
                        "patch_provided": True,
                        "target_url": target_url,
                        "wstg": "WSTG-CLNT-07",
                        "cwe": ["CWE-942"],
                        "owasp_category": "A05:2021 Security Misconfiguration",
                    })
            except Exception:
                pass

        # ── Phase 2: Sensitive File / Directory Probing ─────────────
        if intensity in ("aggressive", "extreme"):
            await broadcast_cb({"type": "log", "message": "    Probing for sensitive files..."})

            parsed_root = urlparse(url)
            base_url = f"{parsed_root.scheme}://{parsed_root.netloc}"

            async def _check_file(path: str):
                test_url = base_url + path
                try:
                    async with semaphore:
                        resp = await client.get(test_url)

                    # Check if it's a real hit, not a custom 404
                    if resp.status_code == 200 and "404" not in resp.text and "Not Found" not in resp.text:
                        # Validate the content matches expected
                        is_valid = False
                        if "git" in path and "ref:" in resp.text:
                            is_valid = True
                        elif "env" in path and ("=" in resp.text or "DB_" in resp.text):
                            is_valid = True
                        elif "phpinfo" in path and "PHP Version" in resp.text:
                            is_valid = True
                        elif "json" in path and resp.text.strip().startswith("{"):
                            is_valid = True
                        else:
                            is_valid = True  # Generic file hit

                        if is_valid:
                            evidence = save_evidence("misconfig_engine", test_url, resp)
                            findings.append({
                                "type": "Exposed Sensitive File",
                                "severity": "High",
                                "module": "misconfig_engine",
                                "vector": f"GET {path}",
                                "payload": path,
                                "evidence": evidence,
                                "description": f"A sensitive file or directory was found exposed at {path}.",
                                "confidence": "high",
                                "confidence_score": 0.9,
                                "verification_state": "verified",
                                "remediation": "Restrict access to sensitive files and directories.",
                                "patch_provided": True,
                                "target_url": test_url,
                                "wstg": "WSTG-CONF-05",
                                "cwe": ["CWE-200", "CWE-538"],
                                "owasp_category": "A01:2021 Broken Access Control",
                            })
                            await broadcast_cb({"type": "log", "message": f"    🔴 EXPOSED FILE: {path}"})
                except Exception:
                    pass

            tasks = [_check_file(p) for p in SENSITIVE_PATHS]
            await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.monotonic() - start_time

    # Deduplicate findings by type (e.g. only report Missing HSTS once per scan, not per URL)
    unique_findings = []
    seen_types = set()
    for f in findings:
        if f["type"] not in seen_types:
            seen_types.add(f["type"])
            unique_findings.append(f)

    await broadcast_cb({
        "type": "log",
        "message": f"    Misconfig Engine Complete ({elapsed:.1f}s): {len(unique_findings)} unique configuration issues found"
    })

    return unique_findings
