"""
AETHER Ffuf Runner / Directory Fuzzer.

Emulates ffuf functionality using our robust async HTTP client for
directory and file brute-forcing, ensuring full portability without 
requiring external binaries.
"""

import asyncio
import logging
import time
from typing import Callable, Awaitable
from urllib.parse import urljoin, urlparse

import httpx

from core.http_client import ScannerAsyncClient
from core.surface_graph import ScanSurfaceGraph
from tools.wordlist_manager import ensure_wordlists

logger = logging.getLogger(__name__)


async def run_dir_fuzzer(
    url: str,
    intensity: str,
    surface_graph: ScanSurfaceGraph,
    broadcast_cb: Callable[[dict], Awaitable[None]],
) -> list[dict]:
    """
    Run directory and file fuzzing against the target URL.
    Returns a list of findings (discovered hidden endpoints).
    """
    findings = []
    start_time = time.monotonic()
    
    await broadcast_cb({"type": "log", "message": "Fuzzer: Preparing wordlists for directory discovery..."})
    
    # Ensure wordlists are downloaded
    wordlists = await ensure_wordlists(broadcast_cb)
    
    target_lists = []
    if intensity in ("stealth", "normal"):
        if wordlists.get("discovery_api"): target_lists.append(wordlists["discovery_api"])
    else:
        if wordlists.get("discovery_web_content"): target_lists.append(wordlists["discovery_web_content"])
        if wordlists.get("discovery_api"): target_lists.append(wordlists["discovery_api"])
    
    if not target_lists:
        await broadcast_cb({"type": "log", "message": "    ✗ No wordlists available. Skipping fuzzing."})
        return []
        
    # Read words into a set to deduplicate
    words = set()
    for wl_path in target_lists:
        try:
            with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        words.add(word)
        except Exception as e:
            logger.error("Failed to read wordlist %s: %s", wl_path, e)
            
    # Sub-sample based on intensity to avoid scanning taking hours
    max_words = {"stealth": 500, "normal": 2000, "aggressive": 10000, "extreme": 30000}.get(intensity, 2000)
    word_list = list(words)[:max_words]
    
    if not word_list:
        return []

    # Get baseline 404 to filter out wildcard 404s
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    wildcard_404_status = 404
    wildcard_404_length = 0
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(urljoin(base_url, "/aether_nonexistent_1337_test"))
            wildcard_404_status = resp.status_code
            wildcard_404_length = len(resp.text)
        except Exception:
            pass

    await broadcast_cb({
        "type": "log",
        "message": f"    Fuzzing {len(word_list)} paths against {base_url} (Baseline 404: {wildcard_404_status})"
    })
    
    concurrency = {"stealth": 5, "normal": 20, "aggressive": 50, "extreme": 100}.get(intensity, 20)
    semaphore = asyncio.Semaphore(concurrency)
    discovered_count = 0
    
    async with ScannerAsyncClient(
        timeout=httpx.Timeout(10.0),
        follow_redirects=False,
        verify=False,
        limits=httpx.Limits(max_connections=concurrency + 10),
    ) as client:
        
        async def _test_path(word: str):
            nonlocal discovered_count
            test_path = f"/{word}" if not word.startswith("/") else word
            test_url = urljoin(base_url, test_path)
            
            # Don't test things we already know about
            if any(test_path in n["url"] for n in surface_graph.targets()):
                return
                
            try:
                async with semaphore:
                    resp = await client.get(test_url)
                    
                # Evaluate if this is a hit
                is_hit = False
                if resp.status_code < 400:
                    is_hit = True
                elif resp.status_code in (401, 403):
                    is_hit = True # Found a protected resource
                elif resp.status_code != wildcard_404_status:
                    # Status code differs from wildcard 404
                    if resp.status_code not in (404, 400):
                        is_hit = True
                elif resp.status_code == wildcard_404_status and abs(len(resp.text) - wildcard_404_length) > 500:
                    # Same status, but wildly different content size (might be custom error vs real page)
                    is_hit = True
                    
                if is_hit:
                    discovered_count += 1
                    surface_graph.add_node(
                        "discovered", test_url,
                        source="fuzzer",
                        metadata={"status": resp.status_code, "length": len(resp.text)}
                    )
                    
                    if resp.status_code in (200, 401, 403):
                        # Add a finding for interesting files (like backups, config files)
                        ext = test_path.split(".")[-1].lower() if "." in test_path else ""
                        if ext in ("bak", "sql", "zip", "tar", "gz", "env", "config", "yml", "yaml", "json"):
                            findings.append({
                                "type": "Exposed Sensitive File (Fuzzed)",
                                "severity": "High",
                                "module": "ffuf_runner",
                                "vector": f"GET {test_path}",
                                "payload": word,
                                "evidence": f"Status: {resp.status_code}\nLength: {len(resp.text)}\nContent snippet:\n{resp.text[:200]}",
                                "description": f"Fuzzing discovered a potentially sensitive file at {test_url}.",
                                "confidence": "high",
                                "confidence_score": 0.8,
                                "verification_state": "verified" if resp.status_code == 200 else "observed",
                                "remediation": "Restrict access to sensitive files. Remove backup or configuration files from the web root.",
                                "patch_provided": True,
                                "target_url": test_url,
                                "wstg": "WSTG-CONF-04",
                                "cwe": ["CWE-425", "CWE-538"],
                            })
                            await broadcast_cb({"type": "log", "message": f"    🔴 FOUND SENSITIVE FILE: {test_url} ({resp.status_code})"})
                        else:
                            # Just log discovery
                            if discovered_count <= 20: # Limit logging noise
                                await broadcast_cb({"type": "log", "message": f"    ✓ Discovered: {test_url} ({resp.status_code})"})
            except Exception:
                pass
                
        # Run tasks in chunks
        chunk_size = 500
        for i in range(0, len(word_list), chunk_size):
            chunk = word_list[i:i + chunk_size]
            tasks = [_test_path(word) for word in chunk]
            await asyncio.gather(*tasks, return_exceptions=True)
            
    elapsed = time.monotonic() - start_time
    await broadcast_cb({
        "type": "log",
        "message": f"    Fuzzer Complete ({elapsed:.1f}s): Discovered {discovered_count} hidden paths."
    })
    
    return findings
