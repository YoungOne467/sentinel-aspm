import logging
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, Vulnerability

logger = logging.getLogger("sentinel.dom_tracker")

DEFAULT_CANARY = "sentinel_taint_123"
DANGEROUS_SINKS = ("eval", "innerHTML", "outerHTML", "document.write", "Function")


def build_dom_xss_finding(url: str, sink: str, evidence: str, canary: str = DEFAULT_CANARY) -> dict[str, Any]:
    return {
        "type": "DOM-XSS",
        "severity": "high",
        "title": f"DOM XSS canary reached {sink}",
        "description": "Dynamic browser instrumentation observed tainted URL input flowing into a dangerous DOM sink.",
        "url": url,
        "sink": sink,
        "payload": canary,
        "evidence": evidence,
        "source": "dom_tracker",
    }


def _canary_urls(url: str, canary: str) -> list[str]:
    parts = urlsplit(url)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    if query_pairs:
        query_pairs = [(key, canary) for key, _ in query_pairs]
    else:
        query_pairs = [("sentinel_taint", canary)]

    query_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query_pairs), parts.fragment))
    fragment_url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, canary))
    return list(dict.fromkeys([query_url, fragment_url]))


async def _persist_vulnerability(finding: dict[str, Any]) -> None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(CrawledURL).where(CrawledURL.url == finding["url"]))
        crawled_url = result.scalars().first()
        if not crawled_url:
            scanned = urlsplit(finding["url"])
            base_url = urlunsplit((scanned.scheme, scanned.netloc, scanned.path, "", ""))
            result = await session.execute(select(CrawledURL).where(CrawledURL.url == base_url))
            crawled_url = result.scalars().first()

        session.add(
            Vulnerability(
                crawled_url_id=crawled_url.id if crawled_url else None,
                target_id=crawled_url.target_id if crawled_url else None,
                vuln_type=finding["type"],
                severity=finding["severity"],
                title=finding["title"],
                description=finding["description"],
                evidence=finding["evidence"],
                sink=finding["sink"],
                payload=finding["payload"],
                source=finding["source"],
                raw_data=finding,
            )
        )
        await session.commit()


async def scan_for_dom_xss(url: str) -> list[dict[str, Any]]:
    """
    Run a Playwright-powered DOM-XSS canary scan.
    Returns structured findings and persists observed sink hits to Vulnerability.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        logger.error("Playwright is required for DOM-XSS scanning: %s", exc)
        return []

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            for test_url in _canary_urls(url, DEFAULT_CANARY):
                page = await browser.new_page()

                def capture(sink: str, evidence: str) -> None:
                    sink_match = evidence.split("sink=", 1)[1].split(";", 1)[0] if "sink=" in evidence else sink
                    if sink_match not in DANGEROUS_SINKS:
                        return
                    key = (test_url, sink, evidence)
                    if key in seen:
                        return
                    seen.add(key)
                    findings.append(build_dom_xss_finding(test_url, sink_match, evidence, DEFAULT_CANARY))

                page.on(
                    "console",
                    lambda msg: capture("console", msg.text)
                    if DEFAULT_CANARY in msg.text and "DOM_XSS_CANARY:" in msg.text
                    else None,
                )

                await page.add_init_script(
                    """
                    (() => {
                      const canary = "sentinel_taint_123";
                      const report = (sink, value) => {
                        try {
                          const text = String(value);
                          if (text.includes(canary)) {
                            console.log(`DOM_XSS_CANARY:sink=${sink};value=${text.slice(0, 180)}`);
                          }
                        } catch (_) {}
                      };

                      const originalEval = window.eval;
                      window.eval = function(value) {
                        report("eval", value);
                        return originalEval.apply(this, arguments);
                      };

                      const originalFunction = window.Function;
                      window.Function = function(...args) {
                        report("Function", args.join("\\n"));
                        return originalFunction.apply(this, args);
                      };

                      const innerHTML = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
                      if (innerHTML && innerHTML.set) {
                        Object.defineProperty(Element.prototype, "innerHTML", {
                          configurable: true,
                          get: innerHTML.get,
                          set(value) {
                            report("innerHTML", value);
                            return innerHTML.set.call(this, value);
                          }
                        });
                      }

                      const outerHTML = Object.getOwnPropertyDescriptor(Element.prototype, "outerHTML");
                      if (outerHTML && outerHTML.set) {
                        Object.defineProperty(Element.prototype, "outerHTML", {
                          configurable: true,
                          get: outerHTML.get,
                          set(value) {
                            report("outerHTML", value);
                            return outerHTML.set.call(this, value);
                          }
                        });
                      }

                      const originalWrite = document.write.bind(document);
                      document.write = function(...args) {
                        report("document.write", args.join(""));
                        return originalWrite(...args);
                      };
                    })();
                    """
                )
                await page.goto(test_url, wait_until="networkidle", timeout=15000)
                await page.wait_for_timeout(500)
                await page.close()
        finally:
            await browser.close()

    for finding in findings:
        try:
            await _persist_vulnerability(finding)
        except Exception as exc:
            logger.debug("Failed to persist DOM-XSS finding for %s: %s", finding["url"], exc)

    return findings
