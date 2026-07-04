"""
AETHER Recursive Web Crawler — Deep Attack Surface Discovery.

A real async BFS crawler that:
1. Recursively follows links within scope to discover all pages
2. Parses HTML to extract forms, parameters, scripts, and API endpoints
3. Fetches and parses robots.txt and sitemap.xml
4. Extracts API endpoints from JavaScript sources
5. Feeds everything into the ScanSurfaceGraph for downstream modules
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx

from core.http_client import ScannerAsyncClient
from core.surface_mapper import extract_surface_from_html, normalize_discovered_url
from core.surface_graph import ScanSurfaceGraph

logger = logging.getLogger(__name__)

# Regex patterns for extracting endpoints from JavaScript
JS_API_PATTERNS = [
    # fetch("/api/users") or axios.get("/api/users")
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](\/[^'"`\s]{2,})[`'"]""", re.IGNORECASE),
    # url: "/api/endpoint"
    re.compile(r"""(?:url|endpoint|path|href|action|src)\s*[:=]\s*[`'"](\/[^'"`\s]{2,})[`'"]""", re.IGNORECASE),
    # "/api/v1/something" as standalone string literal
    re.compile(r"""[`'"](\/(?:api|graphql|rest|v\d+|auth|admin|user|account|internal)[^'"`\s]*)[`'"]""", re.IGNORECASE),
    # window.location = "/path"
    re.compile(r"""(?:window\.location|location\.href|location\.assign)\s*=\s*[`'"](\/[^'"`\s]+)[`'"]""", re.IGNORECASE),
]

# Common paths to check even if not found by crawling
COMMON_DISCOVERY_PATHS = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/wp-json/wp/v2/posts", "/wp-login.php",
    "/.env", "/.git/HEAD", "/.git/config",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env",
    "/debug", "/trace", "/metrics",
    "/admin", "/admin/login", "/dashboard",
    "/phpinfo.php", "/info.php",
    "/login", "/register", "/forgot-password", "/reset-password",
    "/api/health", "/api/status", "/api/config",
    "/console", "/_debug", "/elmah.axd",
]

# File extensions to skip during crawling
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".tar", ".gz",
    ".map",
}


@dataclass
class CrawlConfig:
    """Configuration for the crawler."""
    max_depth: int = 5
    max_pages: int = 200
    max_js_files: int = 30
    concurrency: int = 10
    timeout: float = 15.0
    follow_redirects: bool = True
    discover_common_paths: bool = True
    parse_javascript: bool = True
    respect_robots_txt: bool = True


@dataclass
class CrawlResult:
    """Results from the crawl phase."""
    pages_crawled: int = 0
    js_files_parsed: int = 0
    forms_found: int = 0
    params_found: int = 0
    api_endpoints_found: int = 0
    total_urls_discovered: int = 0
    elapsed_seconds: float = 0.0
    discovered_params: dict[str, set[str]] = field(default_factory=dict)

    def add_params(self, url: str, params: set[str]):
        if url not in self.discovered_params:
            self.discovered_params[url] = set()
        self.discovered_params[url].update(params)
        self.params_found = sum(len(v) for v in self.discovered_params.values())


def _should_skip_url(url: str) -> bool:
    """Check if a URL should be skipped based on file extension."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def _extract_query_params(url: str) -> set[str]:
    """Extract parameter names from a URL's query string."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return set(params.keys())


def _extract_js_endpoints(js_content: str, base_url: str) -> set[str]:
    """Extract API endpoints and paths from JavaScript source code."""
    endpoints = set()
    for pattern in JS_API_PATTERNS:
        for match in pattern.finditer(js_content):
            path = match.group(1)
            normalized = normalize_discovered_url(base_url, path)
            if normalized:
                endpoints.add(normalized)
    return endpoints


async def _parse_robots_txt(client: httpx.AsyncClient, base_url: str) -> set[str]:
    """Parse robots.txt for additional paths to discover."""
    paths = set()
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        resp = await client.get(robots_url, timeout=10)
        if resp.status_code == 200 and "text" in (resp.headers.get("content-type", "")):
            for line in resp.text.splitlines():
                line = line.strip()
                if line.startswith(("Disallow:", "Allow:", "Sitemap:")):
                    _, _, value = line.partition(":")
                    value = value.strip()
                    if value and not value.startswith("#"):
                        if value.startswith("http"):
                            paths.add(value)
                        else:
                            normalized = normalize_discovered_url(base_url, value)
                            if normalized:
                                paths.add(normalized)
    except Exception as e:
        logger.debug("robots.txt fetch failed: %s", e)
    return paths


async def _parse_sitemap(client: httpx.AsyncClient, base_url: str) -> set[str]:
    """Parse sitemap.xml for additional URLs."""
    urls = set()
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    try:
        resp = await client.get(sitemap_url, timeout=10)
        if resp.status_code == 200:
            # Simple regex-based XML parsing (avoids lxml dependency)
            for match in re.finditer(r"<loc>\s*(https?://[^<]+)\s*</loc>", resp.text):
                url = match.group(1).strip()
                normalized = normalize_discovered_url(base_url, url)
                if normalized:
                    urls.add(normalized)
    except Exception as e:
        logger.debug("sitemap.xml fetch failed: %s", e)
    return urls


async def run_crawler(
    target_url: str,
    intensity: str,
    surface_graph: ScanSurfaceGraph,
    broadcast_cb: Callable[[dict], Awaitable[None]],
    config: CrawlConfig | None = None,
) -> CrawlResult:
    """
    Run the recursive web crawler against the target.
    
    Returns a CrawlResult with discovery statistics and all found parameters.
    """
    config = config or CrawlConfig()
    result = CrawlResult()
    start_time = time.monotonic()

    # Adjust config based on intensity
    if intensity == "stealth":
        config.max_pages = 50
        config.concurrency = 2
        config.max_depth = 3
    elif intensity == "aggressive":
        config.max_pages = 500
        config.concurrency = 20
        config.max_depth = 8
    elif intensity == "extreme":
        config.max_pages = 1000
        config.concurrency = 30
        config.max_depth = 10

    await broadcast_cb({
        "type": "log",
        "message": f"🕷️ Crawler: Starting recursive discovery on {target_url} "
                   f"(depth={config.max_depth}, max_pages={config.max_pages})"
    })

    visited: set[str] = set()
    js_visited: set[str] = set()
    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    semaphore = asyncio.Semaphore(config.concurrency)

    # Seed the queue
    queue.put_nowait((target_url, 0))

    async with ScannerAsyncClient(
        timeout=httpx.Timeout(config.timeout),
        follow_redirects=config.follow_redirects,
        verify=False,
        limits=httpx.Limits(max_connections=config.concurrency + 5),
    ) as client:

        # Phase 0: robots.txt + sitemap.xml discovery
        if config.respect_robots_txt:
            robot_paths = await _parse_robots_txt(client, target_url)
            for path in robot_paths:
                if path not in visited:
                    queue.put_nowait((path, 1))
            if robot_paths:
                await broadcast_cb({
                    "type": "log",
                    "message": f"    robots.txt: discovered {len(robot_paths)} additional paths"
                })

        sitemap_urls = await _parse_sitemap(client, target_url)
        for surl in sitemap_urls:
            if surl not in visited:
                queue.put_nowait((surl, 1))
        if sitemap_urls:
            await broadcast_cb({
                "type": "log",
                "message": f"    sitemap.xml: discovered {len(sitemap_urls)} URLs"
            })

        # Phase 0.5: Common path discovery
        if config.discover_common_paths:
            common_found = 0
            common_tasks = []

            async def _check_common_path(path: str):
                nonlocal common_found
                url = urljoin(target_url, path)
                try:
                    async with semaphore:
                        resp = await client.get(url, timeout=8)
                        if resp.status_code < 404 and resp.status_code != 403:
                            common_found += 1
                            surface_graph.add_node(
                                "discovered", url,
                                source="common_paths",
                                classification="discovery",
                            )
                            if url not in visited:
                                queue.put_nowait((url, 1))
                except Exception:
                    pass

            for path in COMMON_DISCOVERY_PATHS:
                common_tasks.append(_check_common_path(path))

            await asyncio.gather(*common_tasks, return_exceptions=True)
            if common_found > 0:
                await broadcast_cb({
                    "type": "log",
                    "message": f"    Common paths: {common_found} accessible endpoints found"
                })

        # Phase 1: BFS Crawl
        async def _crawl_page(url: str, depth: int):
            if url in visited or len(visited) >= config.max_pages:
                return
            if _should_skip_url(url):
                return
            if depth > config.max_depth:
                return

            visited.add(url)

            try:
                async with semaphore:
                    resp = await client.get(url, timeout=config.timeout)
            except Exception as e:
                logger.debug("Crawl failed for %s: %s", url, e)
                return

            result.pages_crawled += 1
            content_type = resp.headers.get("content-type", "")

            # Extract query parameters from this URL
            url_params = _extract_query_params(url)
            if url_params:
                result.add_params(url, url_params)

            # Only parse HTML responses
            if "html" not in content_type.lower():
                surface_graph.add_node("resource", url, source="crawler")
                return

            # Parse HTML for links, forms, scripts, API endpoints
            surface = extract_surface_from_html(url, resp.text)
            surface_graph.merge_surface(url, surface)

            # Track forms and their parameters
            for form in surface.get("forms", []):
                result.forms_found += 1
                form_params = set(form.get("inputs", []))
                action = form.get("action", url)
                if form_params:
                    result.add_params(action, form_params)
                    surface_graph.add_node(
                        "form", action,
                        method=form.get("method", "GET"),
                        source="crawler",
                        params=form_params,
                    )

            # Queue discovered links
            for link in surface.get("links", []):
                if link not in visited and len(visited) < config.max_pages:
                    queue.put_nowait((link, depth + 1))

            # Queue API endpoints from HTML/JS
            for endpoint in surface.get("api_candidates", []):
                result.api_endpoints_found += 1
                surface_graph.add_node("api", endpoint, source="html_analysis")
                if endpoint not in visited:
                    queue.put_nowait((endpoint, depth + 1))

            # Parse external JavaScript files
            if config.parse_javascript:
                for script_url in surface.get("scripts", []):
                    if script_url not in js_visited and len(js_visited) < config.max_js_files:
                        js_visited.add(script_url)
                        try:
                            async with semaphore:
                                js_resp = await client.get(script_url, timeout=10)
                            if js_resp.status_code == 200 and len(js_resp.text) < 2_000_000:
                                js_endpoints = _extract_js_endpoints(js_resp.text, target_url)
                                for ep in js_endpoints:
                                    result.api_endpoints_found += 1
                                    surface_graph.add_node("api", ep, source="javascript_analysis")
                                    if ep not in visited:
                                        queue.put_nowait((ep, depth + 1))
                                result.js_files_parsed += 1
                        except Exception as e:
                            logger.debug("JS parse failed for %s: %s", script_url, e)

            # Progress update every 20 pages
            if result.pages_crawled % 20 == 0:
                await broadcast_cb({
                    "type": "log",
                    "message": f"    Crawler: {result.pages_crawled} pages crawled, "
                               f"{surface_graph.to_dict()['node_count']} surface nodes..."
                })

        # Run BFS with worker pool
        active_workers = 0
        workers_done = asyncio.Event()

        async def _worker():
            while True:
                try:
                    url, depth = await queue.get()
                except asyncio.CancelledError:
                    break

                try:
                    await _crawl_page(url, depth)
                finally:
                    queue.task_done()

        # ⚡ Bolt: Use persistent worker tasks and `queue.join()` instead of spawning/destroying
        # short-lived batches with artificial sleep delays. This guarantees true concurrency
        # up to the config limit and eliminates arbitrary IO blocking.
        workers = []
        for _ in range(config.concurrency):
            workers.append(asyncio.create_task(_worker()))

        await queue.join()

        for w in workers:
            w.cancel()

        await asyncio.gather(*workers, return_exceptions=True)

    result.total_urls_discovered = len(visited)
    result.elapsed_seconds = time.monotonic() - start_time

    # Final summary
    graph_data = surface_graph.to_dict()
    await broadcast_cb({
        "type": "log",
        "message": f"🕷️ Crawler Complete ({result.elapsed_seconds:.1f}s):\n"
                   f"    Pages: {result.pages_crawled} | "
                   f"Forms: {result.forms_found} | "
                   f"JS Files: {result.js_files_parsed} | "
                   f"API Endpoints: {result.api_endpoints_found}\n"
                   f"    Surface Nodes: {graph_data['node_count']} | "
                   f"Unique Params: {result.params_found}"
    })

    return result
