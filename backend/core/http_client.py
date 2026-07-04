import httpx
import asyncio
import os
import random
import urllib.parse
import logging
from core.request_context import get_scan_context_headers

from core.http_pool import HTTPClientPool

logger = logging.getLogger(__name__)

_global_rate_limit_semaphore = asyncio.Semaphore(15)  # Hard limit of 15 concurrency to prevent socket exhaustion
_host_semaphores = {}
_host_penalties = {} # Tracks host-specific delay penalties on 429s
_host_concurrency_limits = {}

def _get_global_request_headers():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    ]
    return {
        "User-Agent": random.choice(user_agents),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

class ScannerAsyncClient(httpx.AsyncClient):
    """
    A custom wrapper around httpx.AsyncClient that implements:
    - Retry logic and backoff.
    - Rate limit (429) tracking per host.
    - Jitter and stealth headers to evade simple WAFs.
    """
    def __init__(self, *args, jitter_enabled=True, auth_profile: dict = None, **kwargs):
        self._client_verify = kwargs.get("verify", True)
        super().__init__(*args, **kwargs)
        self.jitter_enabled = jitter_enabled
        self.auth_profile = auth_profile or {}
        self._auth_event = asyncio.Event()
        self._auth_event.set()
        self._successful_endpoints = set()

    async def request(self, method, url, *args, **kwargs):
        # Wait if the system is under resource pressure (RAM/CPU)
        from core.resource_governor import system_healthy
        await system_healthy.wait()

        # Wait if authentication refresh is currently in progress
        await self._auth_event.wait()

        max_retries = 3
        base_delay = 2.5
        
        waf_profile = None
        try:
            from core.waf_detector import adapt_url_for_waf, get_cached_waf_profile

            waf_profile = get_cached_waf_profile(str(url))
            url = adapt_url_for_waf(str(url), waf_profile)
        except Exception as exc:
            logger.debug("WAF adaptation lookup skipped for %s: %s", url, exc)

        parsed_url = urllib.parse.urlparse(str(url))
        host = parsed_url.netloc
        
        if host not in _host_semaphores:
            _host_semaphores[host] = asyncio.Semaphore(25)
            _host_penalties[host] = 0.0
            _host_concurrency_limits[host] = 25

        if waf_profile and waf_profile.get("detected"):
            adaptation = waf_profile.get("adaptation") or {}
            concurrency_limit = int(adaptation.get("concurrency_limit") or 25)
            current_limit = int(_host_concurrency_limits.get(host, 25))
            if concurrency_limit < current_limit and _host_concurrency_limits.get(host) == current_limit:
                # Only tighten if no other coroutine already lowered it; reuse existing
                # semaphore to avoid orphaning waiters — we can't shrink a live semaphore,
                # so just record the new limit for future host initialization.
                _host_concurrency_limits[host] = concurrency_limit
            jitter_range = adaptation.get("jitter_range") or [0.5, 3.5]
            _host_penalties[host] = max(float(_host_penalties.get(host, 0.0)), float(jitter_range[0]))

        headers = kwargs.get("headers") or {}
        if isinstance(headers, httpx.Headers):
            headers = dict(headers.multi_items())
        elif not isinstance(headers, dict):
            headers = dict(headers)
            
        # Merge client-level headers
        for k, v in self.headers.items():
            if k not in headers:
                headers[k] = v

        scan_headers = get_scan_context_headers()
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for k, v in scan_headers.items():
            if k.lower() not in headers_lower:
                headers[k] = v
                headers_lower[k.lower()] = v

        # Inject current auth credentials if available
        if self.auth_profile and "tokens" in self.auth_profile:
            tokens = self.auth_profile["tokens"]
            if "headers" in tokens:
                for k, v in tokens["headers"].items():
                    if k.lower() not in headers_lower:
                        headers[k] = v
                        headers_lower[k.lower()] = v
            if "cookies" in tokens:
                self.cookies.update(tokens["cookies"])

        try:
            from core.attack_chainer import exploit_context

            context_headers = exploit_context.get_auth_headers(str(url))
            for k, v in context_headers.items():
                if k.lower() not in headers_lower:
                    headers[k] = v
                    headers_lower[k.lower()] = v
        except Exception as exc:
            logger.debug("Exploit context auth injection skipped for %s: %s", url, exc)

        default_headers = _get_global_request_headers()
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # ⚡ Bolt: Use pre-computed lowercase keys instead of calculating k.lower() repeatedly
        for k, v in default_headers.items():
            k_lower = k.lower()
            if k_lower not in headers_lower:
                headers[k] = v
                headers_lower[k_lower] = v

        # Inject custom evasion headers
        try:
            from core.evasion_manager import load_evasion_settings
            evasion_settings = load_evasion_settings()
            custom_headers = evasion_settings.get("custom_headers") or {}
            for k, v in custom_headers.items():
                k_lower = k.lower()
                if k_lower not in headers_lower:
                    headers[k] = v
                    headers_lower[k_lower] = v
        except Exception as exc:
            logger.debug("Custom evasion headers injection skipped: %s", exc)

        if os.getenv("OOB_INJECTION_ENABLED", "1") != "0":
            try:
                from core.oob_tracker import generate_oob_headers

                oob_headers = await generate_oob_headers(str(url))
                # ⚡ Bolt: Removed redundant `headers_lower` re-initialization. It was allocating
                # a new dictionary for every single outbound request unnecessarily.
                for k, v in oob_headers.items():
                    k_lower = k.lower()
                    if k_lower not in headers_lower:
                        headers[k] = v
                        headers_lower[k_lower] = v
            except Exception as exc:
                logger.debug("OOB header injection skipped for %s: %s", url, exc)
                
        sanitized_headers = {k: str(v).replace('\r', '').replace('\n', '') for k, v in headers.items()}
        kwargs["headers"] = sanitized_headers

        for attempt in range(max_retries + 1):
            async with _global_rate_limit_semaphore:
                async with _host_semaphores.get(host, asyncio.Semaphore(25)):
                    if _host_penalties.get(host, 0) > 0:
                        await asyncio.sleep(_host_penalties[host])
                    
                    try:
                        pooled_client = await HTTPClientPool.get_client()
                        req_kwargs = kwargs.copy()
                        if "timeout" not in req_kwargs:
                            req_kwargs["timeout"] = self.timeout
                        if "follow_redirects" not in req_kwargs:
                            req_kwargs["follow_redirects"] = self.follow_redirects
                        if "verify" not in req_kwargs:
                            req_kwargs["verify"] = getattr(self, "_client_verify", True)

                        req_cookies = req_kwargs.pop("cookies", None)
                        merged_cookies = httpx.Cookies(self.cookies)
                        if req_cookies is not None:
                            merged_cookies.update(req_cookies)

                        resp = await pooled_client.request(method, url, cookies=merged_cookies, *args, **req_kwargs)
                        if resp.status_code == 200:
                            self._successful_endpoints.add(str(url))

                        # Check if previously successful endpoint now fails with 401/403
                        if resp.status_code in (401, 403) and str(url) in self._successful_endpoints and self.auth_profile.get("login_url") and self.auth_profile.get("credentials"):
                            if self._auth_event.is_set():
                                self._auth_event.clear()  # Pause other requests
                                logger.warning("Endpoint %s returned %s after previous 200 OK. Pausing client queue for token refresh.", url, resp.status_code)
                                try:
                                    from core.auth_manager import acquire_session
                                    new_tokens = await acquire_session(
                                        self.auth_profile["login_url"],
                                        self.auth_profile["credentials"]
                                    )
                                    self.auth_profile["tokens"] = new_tokens
                                    logger.info("Authentication token refreshed successfully.")
                                except Exception as refresh_exc:
                                    logger.error("Failed to refresh authentication session: %s", refresh_exc)
                                finally:
                                    self._auth_event.set()  # Resume other requests

                            # Wait for active refresh to complete
                            await self._auth_event.wait()

                            # Apply new auth credentials to retry request
                            if "tokens" in self.auth_profile:
                                tokens = self.auth_profile["tokens"]
                                if "headers" in tokens:
                                    for k, v in tokens["headers"].items():
                                        headers[k] = v
                                if "cookies" in tokens:
                                    self.cookies.update(tokens["cookies"])

                            sanitized_headers = {k: str(v).replace('\r', '').replace('\n', '') for k, v in headers.items()}
                            kwargs["headers"] = sanitized_headers

                            logger.info("Retrying request to %s with refreshed session tokens.", url)
                            
                            req_kwargs = kwargs.copy()
                            if "timeout" not in req_kwargs:
                                req_kwargs["timeout"] = self.timeout
                            if "follow_redirects" not in req_kwargs:
                                req_kwargs["follow_redirects"] = self.follow_redirects
                            if "verify" not in req_kwargs:
                                req_kwargs["verify"] = getattr(self, "_client_verify", True)

                            req_cookies = req_kwargs.pop("cookies", None)
                            merged_cookies = httpx.Cookies(self.cookies)
                            if req_cookies is not None:
                                merged_cookies.update(req_cookies)

                            resp = await pooled_client.request(method, url, cookies=merged_cookies, *args, **req_kwargs)

                    except Exception as e:
                        if attempt < max_retries:
                            wait_time = base_delay * (2 ** attempt)
                            logger.warning("Connection error ({str(e)[:50]}) at %s. Retrying in {wait_time:.1f}s...", url)
                            res = asyncio.sleep(wait_time)
                            if res is not None:
                                await res
                            continue
                        return httpx.Response(500, content=b"Permanent Connection Failure", request=httpx.Request(method, url))
                
            if resp.status_code == 429 and attempt < max_retries:
                _host_penalties[host] = min(_host_penalties.get(host, 0) + 1.0, 10.0) 
                wait_time = (base_delay * (2 ** attempt)) + (random.random() * 5)
                logger.warning("429 Rate Limit at %s. Penalty increased to {_host_penalties[host]:.1f}s. Retrying in {wait_time:.1f}s...", host)
                res = asyncio.sleep(wait_time)
                if res is not None:
                    await res
                
                # Rotate identity on 429
                headers.update(_get_global_request_headers())
                kwargs["headers"] = headers
            else:
                if resp.status_code < 400:
                    min_penalty = 0.0
                    if waf_profile and waf_profile.get("detected"):
                        jitter_range = (waf_profile.get("adaptation") or {}).get("jitter_range") or [0.0, 0.0]
                        min_penalty = float(jitter_range[0])
                    _host_penalties[host] = max(_host_penalties.get(host, 0) - 0.2, min_penalty)
                
                if self.jitter_enabled:
                    jitter_low, jitter_high = 0.5, 3.5
                    if waf_profile and waf_profile.get("detected"):
                        jitter_range = (waf_profile.get("adaptation") or {}).get("jitter_range") or [jitter_low, jitter_high]
                        jitter_low, jitter_high = float(jitter_range[0]), float(jitter_range[1])
                    jitter = random.uniform(jitter_low, jitter_high) if attempt == 0 else 0
                    if jitter > 0:
                        try:
                            res = asyncio.sleep(jitter)
                            if res is not None:
                                await res
                        except asyncio.CancelledError:
                            raise
                    
                return resp
                
        return resp
