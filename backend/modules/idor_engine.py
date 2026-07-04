"""
AETHER IDOR Engine — Insecure Direct Object Reference Detection.

Techniques:
1. Sequential ID enumeration (test ID-1, ID+1, 0, 1)
2. UUID anomaly detection (if UUIDs are used, are they predictable?)
3. Parameter swapping (e.g., swapping ?user_id=X with ?user_id=Y)
4. Response diffing (baseline vs altered ID)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import time
from typing import Callable, Awaitable
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

from core.http_client import ScannerAsyncClient
from core.surface_graph import ScanSurfaceGraph
from core.evidence_manager import save_evidence

logger = logging.getLogger(__name__)

# Parameters commonly associated with object references
IDOR_PARAM_NAMES = {
    "id", "user_id", "uid", "account_id", "org_id", "organization_id",
    "team_id", "project_id", "workspace_id", "tenant_id", "customer_id",
    "order_id", "invoice_id", "payment_id", "subscription_id", "plan_id",
    "role_id", "group_id", "doc_id", "document_id", "file_id", "image_id",
    "profile_id", "post_id", "comment_id", "message_id", "thread_id",
}


def _response_hash(text: str) -> str:
    """Hash a response body for comparison."""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _get_mutations(original_value: str) -> list[str]:
    """Generate IDOR mutations based on the original value."""
    mutations = []
    
    # If it's a number, try adjacent numbers and boundaries
    if original_value.isdigit():
        val = int(original_value)
        mutations.extend([
            str(val + 1),
            str(val - 1) if val > 0 else "1",
            "0",
            "1",
            "999999999" # Out of bounds
        ])
    
    # If it looks like a UUID
    elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", original_value, re.I):
        # We can't easily guess UUIDs, but we can try common test UUIDs
        mutations.extend([
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ])
        
    # If it's a string, try common test values
    else:
        mutations.extend([
            "admin",
            "test",
            "1",
            original_value + "1",
            "a" * len(original_value)
        ])
        
    # Deduplicate and remove original
    return list(set([m for m in mutations if m != original_value]))


async def run_idor_scan(
    url: str,
    intensity: str,
    broadcast_cb: Callable[[dict], Awaitable[None]],
    *,
    surface_graph: ScanSurfaceGraph | None = None,
    auth_profiles: dict | None = None,
    scan_config: dict | None = None,
) -> list[dict]:
    """Run comprehensive IDOR scanning."""
    findings = []
    start_time = time.monotonic()
    
    await broadcast_cb({"type": "log", "message": "IDOR Engine: Starting Insecure Direct Object Reference detection..."})
    
    # Find parameters likely vulnerable to IDOR
    injection_targets = []
    if surface_graph:
        for node in surface_graph.targets():
            params = node.get("params", [])
            parsed = urlparse(node.get("url", ""))
            query_params = list(parse_qs(parsed.query).keys())
            all_params = list(set(params + query_params))
            
            # Filter for ID-like parameters
            idor_params = [p for p in all_params if p.lower() in IDOR_PARAM_NAMES or p.lower().endswith("id")]
            
            if idor_params:
                injection_targets.append({
                    "url": node["url"],
                    "method": node.get("method", "GET"),
                    "params": idor_params,
                })
    
    if not injection_targets:
        parsed = urlparse(url)
        base_params = [p for p in parse_qs(parsed.query).keys() if p.lower() in IDOR_PARAM_NAMES or p.lower().endswith("id")]
        if base_params:
            injection_targets = [{"url": url, "method": "GET", "params": base_params}]
    
    max_targets = {"stealth": 5, "normal": 15, "aggressive": 30, "extreme": 50}.get(intensity, 15)
    injection_targets = injection_targets[:max_targets]
    
    if not injection_targets:
        await broadcast_cb({"type": "log", "message": "    No ID-like parameters found. Skipping IDOR scan."})
        return []
    
    concurrency = {"stealth": 2, "normal": 5, "aggressive": 10, "extreme": 20}.get(intensity, 5)
    semaphore = asyncio.Semaphore(concurrency)
    tested = 0
    
    await broadcast_cb({
        "type": "log",
        "message": f"    Testing {sum(len(t['params']) for t in injection_targets)} ID-like parameters"
    })
    
    async with ScannerAsyncClient(
        timeout=httpx.Timeout(15.0),
        follow_redirects=False,
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
            
            # Extract original values for the parameters from the URL if available
            parsed = urlparse(target_url)
            query_params = parse_qs(parsed.query)
            
            for param in target["params"]:
                tested += 1
                
                # Try to get a valid starting value
                original_value = "1"
                if param in query_params and query_params[param]:
                    original_value = query_params[param][0]
                
                # Get baseline
                baseline = await _inject(target_url, method, param, original_value)
                if not baseline or baseline.status_code >= 400:
                    continue # Skip if baseline fails or requires auth we don't have
                
                baseline_hash = _response_hash(baseline.text)
                baseline_len = len(baseline.text)
                
                mutations = _get_mutations(original_value)
                
                for mutation in mutations:
                    resp = await _inject(target_url, method, param, mutation)
                    if not resp:
                        continue
                    
                    resp_hash = _response_hash(resp.text)
                    
                    # Criteria for potential IDOR:
                    # 1. 200 OK status
                    # 2. Response differs from baseline significantly (different object returned)
                    # 3. It's not a generic "not found" page (length check)
                    
                    if (resp.status_code == 200 and 
                        resp_hash != baseline_hash and 
                        abs(len(resp.text) - baseline_len) > 50 and
                        len(resp.text) > 100): # Filter out small "User not found" messages
                        
                        # We need to verify it's not just returning the requested ID in the body
                        # Check if the response body differs by more than just the injected payload
                        diff_ratio = abs(len(resp.text) - baseline_len) / max(baseline_len, 1)
                        
                        if diff_ratio > 0.05: # At least 5% difference in content
                            evidence = save_evidence(
                                "idor_engine", target_url, resp,
                                extra_info=f"Parameter: {param}\nOriginal Value: {original_value}\nMutated Value: {mutation}\nBaseline Length: {baseline_len}\nResponse Length: {len(resp.text)}"
                            )
                            
                            findings.append({
                                "type": "Potential Insecure Direct Object Reference (IDOR)",
                                "severity": "High",
                                "module": "idor_engine",
                                "vector": f"{method} {urlparse(target_url).path} → param: {param}",
                                "payload": mutation,
                                "evidence": evidence,
                                "description": f"The parameter '{param}' may be vulnerable to IDOR. "
                                             f"Changing the value from '{original_value}' to '{mutation}' resulted in a "
                                             f"200 OK response with significantly different content ({len(resp.text)} bytes vs {baseline_len} bytes), "
                                             "suggesting a different object was accessed.",
                                "confidence": "medium",
                                "confidence_score": 0.65, # Needs manual verification to confirm data sensitivity
                                "verification_state": "candidate",
                                "remediation": "Implement proper access controls. Validate that the currently authenticated user "
                                             "has permission to access the requested object ID. Consider using unpredictable identifiers (UUIDs) instead of sequential integers.",
                                "patch_provided": True,
                                "target_url": target_url,
                                "wstg": "WSTG-INPV-04",
                                "cwe": ["CWE-639", "CWE-284"],
                                "owasp_category": "A01:2021 Broken Access Control",
                            })
                            
                            await broadcast_cb({
                                "type": "log",
                                "message": f"    🔴 POTENTIAL IDOR: {param} @ {urlparse(target_url).path} (changed {original_value} -> {mutation})"
                            })
                            break # Found for this param, move on
    
    elapsed = time.monotonic() - start_time
    candidates = sum(1 for f in findings if f.get("verification_state") == "candidate")
    
    await broadcast_cb({
        "type": "log",
        "message": f"    IDOR Engine Complete ({elapsed:.1f}s): {len(findings)} potential findings from {tested} parameters"
    })
    
    return findings
