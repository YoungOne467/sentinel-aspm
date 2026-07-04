"""
JavaScript Deep Analyzer — async scraping and parsing of JS files.
Extracts: hidden endpoints, API keys/tokens, developer comments, relative URLs.
Uses optimized regex rule sets for high-confidence extraction.
"""
import asyncio
import logging
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

import httpx

from core.database import AsyncSessionLocal, batch_writer
from core.models import JSFinding, gen_id

logger = logging.getLogger(__name__)

# ─── Regex Rule Sets ───────────────────────────────────────────────────────────

_RULES = {
    "api_key": {
        "patterns": [
            r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,64})['"]""",
            r"""(?:AKIA[0-9A-Z]{16})""",  # AWS Access Key
            r"""(?:sk-[a-zA-Z0-9]{32,})""",  # OpenAI-style key
            r"""(?:ghp_[a-zA-Z0-9]{36})""",  # GitHub PAT
            r"""(?:glpat-[a-zA-Z0-9_\-]{20,})""",  # GitLab PAT
            r"""(?:Bearer\s+[a-zA-Z0-9_\-\.]{20,})""",
        ],
        "confidence": 0.85,
    },
    "endpoint": {
        "patterns": [
            r"""['"](?:\/api\/[a-zA-Z0-9_\-\/\.:{}]+)['"]""",
            r"""['"](?:\/v[1-9]\/[a-zA-Z0-9_\-\/\.:{}]+)['"]""",
            r"""fetch\s*\(\s*['"]([^'"]+)['"]""",
            r"""axios\.[a-z]+\s*\(\s*['"]([^'"]+)['"]""",
            r"""\.(?:get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]""",
        ],
        "confidence": 0.7,
    },
    "secret": {
        "patterns": [
            r"""(?:password|passwd|pwd|secret|token)\s*[:=]\s*['"]([^'"]{4,})['"]""",
            r"""(?:private[_-]?key)\s*[:=]\s*['"]([^'"]+)['"]""",
            r"""(?:-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----)""",
            r"""(?:mongodb(?:\+srv)?:\/\/[^\s'"]+)""",
            r"""(?:postgres(?:ql)?:\/\/[^\s'"]+)""",
            r"""(?:mysql:\/\/[^\s'"]+)""",
        ],
        "confidence": 0.9,
    },
    "comment": {
        "patterns": [
            r"""\/\/\s*(TODO|FIXME|HACK|BUG|XXX|SECURITY|VULNERABLE|DEBUG)[:\s]+(.{5,80})""",
            r"""\/\*\s*(TODO|FIXME|HACK|BUG|XXX|SECURITY)[:\s]+(.{5,80})\s*\*\/""",
        ],
        "confidence": 0.6,
    },
}

# ─── JS Source Discovery ───────────────────────────────────────────────────────

_SCRIPT_PATTERN = re.compile(
    r"""<script[^>]+src\s*=\s*['"]([^'"]+\.js[^'"]*)['"]""", re.IGNORECASE
)


class JSAnalyzer:
    """Scrapes and analyzes JavaScript files from web targets."""

    def __init__(self, max_concurrent: int = 3, timeout: float = 15.0):
        self._sem = asyncio.Semaphore(max_concurrent)
        self._timeout = timeout

    async def analyze_target(self, target_id: str, base_url: str) -> Dict[str, Any]:
        """
        Discover and analyze JS files for a target.
        Returns summary stats.
        """
        js_urls = await self._discover_js_files(base_url)
        logger.info("Discovered %d JS files for %s", len(js_urls), base_url)

        all_findings: List[Dict[str, Any]] = []
        tasks = [self._analyze_js_url(url) for url in js_urls[:20]]  # Cap at 20
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)

        # Store findings
        stored = 0
        for f in all_findings:
            js_finding = JSFinding(
                id=gen_id(),
                target_id=target_id,
                source_url=f["source_url"],
                finding_type=f["type"],
                value=f["value"],
                context=f.get("context", ""),
                confidence=f.get("confidence", 0.5),
            )
            await batch_writer.enqueue(js_finding)
            stored += 1

        await batch_writer.flush()

        stats = {
            "js_files_found": len(js_urls),
            "js_files_analyzed": min(len(js_urls), 20),
            "findings": stored,
            "by_type": {},
        }
        for f in all_findings:
            t = f["type"]
            stats["by_type"][t] = stats["by_type"].get(t, 0) + 1

        return stats

    async def _discover_js_files(self, base_url: str) -> List[str]:
        """Fetch the page HTML and extract <script src="..."> URLs."""
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(base_url)
                html = resp.text
        except Exception as e:
            logger.error("Failed to fetch %s: %s", base_url, e)
            return []

        matches = _SCRIPT_PATTERN.findall(html)
        urls = []
        for src in matches:
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = urljoin(base_url, src)
            elif not src.startswith("http"):
                src = urljoin(base_url, src)
            urls.append(src)

        return list(set(urls))

    async def _analyze_js_url(self, url: str) -> List[Dict[str, Any]]:
        """Download and scan a single JS file."""
        async with self._sem:
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        return []
                    content = resp.text
            except Exception as e:
                logger.debug("Failed to fetch JS %s: %s", url, e)
                return []

        # Cap content size to prevent regex catastrophic backtracking
        if len(content) > 2_000_000:
            content = content[:2_000_000]

        findings = []
        for rule_type, rule in _RULES.items():
            for pattern in rule["patterns"]:
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        value = match.group(1) if match.lastindex else match.group(0)
                        # Extract context (surrounding 40 chars)
                        start = max(0, match.start() - 40)
                        end = min(len(content), match.end() + 40)
                        context = content[start:end].replace("\n", " ").strip()

                        findings.append({
                            "source_url": url,
                            "type": rule_type,
                            "value": value[:500],
                            "context": context[:300],
                            "confidence": rule["confidence"],
                        })
                except re.error:
                    continue

        return findings


# Global singleton
js_analyzer = JSAnalyzer(max_concurrent=3)
