"""
AETHER Parameter Miner — Hidden Parameter Discovery.

Brute-forces common parameter names against discovered endpoints to find
hidden/undocumented parameters that may be vulnerable to injection.

Technique: Send requests with candidate parameters and use response
diffing to detect when a parameter causes a behavior change.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from typing import Callable, Awaitable
from urllib.parse import urlparse, urlencode, urljoin

import httpx

from core.http_client import ScannerAsyncClient
from core.surface_graph import ScanSurfaceGraph

logger = logging.getLogger(__name__)

# High-value parameter names commonly found in bug bounty targets
PARAM_WORDLIST = [
    # Auth & identity
    "id", "user_id", "uid", "user", "username", "email", "token", "api_key",
    "apikey", "key", "secret", "password", "passwd", "pass", "auth", "session",
    "sid", "jwt", "access_token", "refresh_token", "oauth_token",
    # Data access
    "file", "filename", "path", "dir", "folder", "document", "doc", "page",
    "url", "uri", "src", "source", "dest", "destination", "target", "next",
    "return", "returnUrl", "return_url", "redirect", "redirect_uri", "goto",
    "continue", "callback", "cb", "ref", "referer",
    # Query & filter
    "q", "query", "search", "s", "keyword", "filter", "sort", "order",
    "orderby", "order_by", "sortby", "sort_by", "limit", "offset", "skip",
    "count", "per_page", "page", "p", "start", "end", "from", "to",
    "min", "max", "status", "state", "type", "category", "cat", "tag",
    # Actions & operations
    "action", "cmd", "command", "exec", "execute", "run", "do", "op",
    "operation", "method", "func", "function", "module", "mode", "step",
    "format", "output", "view", "template", "tpl", "theme", "lang",
    "locale", "language", "debug", "test", "verbose", "raw", "preview",
    # IDOR targets
    "account_id", "account", "org_id", "organization_id", "team_id",
    "project_id", "workspace_id", "tenant_id", "customer_id", "order_id",
    "invoice_id", "payment_id", "subscription_id", "plan_id", "role",
    "role_id", "group_id", "group", "admin", "is_admin", "privilege",
    # Tech-specific
    "include", "require", "load", "read", "fetch", "import", "config",
    "conf", "settings", "env", "environment", "db", "database", "table",
    "column", "field", "select", "where", "join", "xml", "json", "data",
    "body", "content", "text", "html", "payload", "input", "value",
    "name", "title", "description", "comment", "message", "note",
    # SSRF targets
    "webhook", "webhook_url", "notify_url", "ping", "host", "hostname",
    "server", "proxy", "proxy_url", "forward", "forward_to", "ip",
    "domain", "site", "link", "image_url", "avatar_url", "icon_url",
    "feed", "rss", "atom", "xml_url", "wsdl", "endpoint",
]


def _response_hash(text: str) -> str:
    """Hash a response body for comparison."""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


async def run_param_miner(
    target_url: str,
    intensity: str,
    surface_graph: ScanSurfaceGraph,
    broadcast_cb: Callable[[dict], Awaitable[None]],
) -> dict:
    """
    Mine for hidden parameters on discovered endpoints.
    
    Returns a dict mapping endpoint URLs to sets of discovered parameter names.
    """
    start_time = time.monotonic()
    discovered: dict[str, set[str]] = {}
    
    # Get endpoints from the surface graph to test
    targets = surface_graph.targets(kinds={"page", "api", "form", "discovered"})
    
    # Limit based on intensity
    max_targets = {"stealth": 5, "normal": 20, "aggressive": 50, "extreme": 100}.get(intensity, 20)
    max_params = {"stealth": 30, "normal": 80, "aggressive": len(PARAM_WORDLIST), "extreme": len(PARAM_WORDLIST)}.get(intensity, 80)
    
    test_targets = targets[:max_targets]
    test_params = PARAM_WORDLIST[:max_params]
    
    if not test_targets:
        # Fall back to just the target URL if no surface nodes exist yet
        test_targets = [{"url": target_url, "method": "GET"}]
    
    await broadcast_cb({
        "type": "log",
        "message": f"🔍 Param Miner: Testing {len(test_params)} parameter names across {len(test_targets)} endpoints"
    })
    
    concurrency = {"stealth": 2, "normal": 5, "aggressive": 10, "extreme": 20}.get(intensity, 5)
    semaphore = asyncio.Semaphore(concurrency)
    
    async with ScannerAsyncClient(
        timeout=httpx.Timeout(12.0),
        follow_redirects=True,
        verify=False,
        jitter_enabled=False,
    ) as client:
        
        async def _process_target(target):
            url = target["url"]
            method = target.get("method", "GET").upper()
            
            # Get baseline response (no extra params)
            try:
                async with semaphore:
                    if method == "GET":
                        baseline = await client.get(url)
                    else:
                        baseline = await client.post(url, data={})
            except Exception:
                return
            
            baseline_hash = _response_hash(baseline.text)
            baseline_length = len(baseline.text)
            baseline_status = baseline.status_code
            
            endpoint_params: set[str] = set()
            
            # Test parameters in batches for efficiency
            batch_size = 20
            for i in range(0, len(test_params), batch_size):
                batch = test_params[i:i + batch_size]
                
                async def _test_param(param: str):
                    try:
                        async with semaphore:
                            if method == "GET":
                                test_url = f"{url}{'&' if '?' in url else '?'}{param}=AETHER_PROBE_7331"
                                resp = await client.get(test_url)
                            else:
                                resp = await client.post(url, data={param: "AETHER_PROBE_7331"})
                        
                        resp_hash = _response_hash(resp.text)
                        resp_length = len(resp.text)
                        
                        # Detect behavior change
                        if resp_hash != baseline_hash:
                            length_diff = abs(resp_length - baseline_length)
                            # Ignore tiny changes (likely just the param being reflected)
                            if length_diff > 50 or resp.status_code != baseline_status:
                                endpoint_params.add(param)
                                surface_graph.add_node(
                                    "param_mined", url,
                                    method=method,
                                    source="param_miner",
                                    params=[param],
                                    metadata={"status_change": resp.status_code != baseline_status,
                                              "length_diff": length_diff},
                                )
                    except Exception:
                        pass
                
                tasks = [_test_param(p) for p in batch]
                await asyncio.gather(*tasks, return_exceptions=True)
            
            if endpoint_params:
                discovered[url] = endpoint_params
                await broadcast_cb({
                    "type": "log",
                    "message": f"    ✓ {urlparse(url).path}: found {len(endpoint_params)} hidden params: {', '.join(sorted(endpoint_params)[:8])}{'...' if len(endpoint_params) > 8 else ''}"
                })

        # Process all targets concurrently
        target_tasks = [_process_target(target) for target in test_targets]
        await asyncio.gather(*target_tasks, return_exceptions=True)
    
    elapsed = time.monotonic() - start_time
    total_params = sum(len(v) for v in discovered.values())
    
    await broadcast_cb({
        "type": "log",
        "message": f"🔍 Param Miner Complete ({elapsed:.1f}s): {total_params} hidden parameters across {len(discovered)} endpoints"
    })
    
    return discovered
