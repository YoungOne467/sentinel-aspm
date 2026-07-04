import pytest


class FakeHTTPResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


@pytest.mark.asyncio
async def test_waf_detector_fingerprints_cloudflare_and_caches_profile(monkeypatch):
    from core import waf_detector

    waf_detector.clear_waf_profile_cache()
    requested_urls = []

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            requested_urls.append(url)
            if len(requested_urls) == 1:
                return FakeHTTPResponse("ok", status_code=200, headers={"Server": "cloudflare"})
            return FakeHTTPResponse(
                "<html>Attention Required! | Cloudflare</html>",
                status_code=403,
                headers={"CF-Ray": "abc", "Server": "cloudflare"},
            )

    monkeypatch.setattr(waf_detector.httpx, "AsyncClient", FakeClient)

    result = await waf_detector.detect_waf("https://target.local/app")

    assert result["detected"] is True
    assert result["provider"] == "cloudflare"
    assert result["block_status"] == 403
    assert result["adaptation"]["concurrency_limit"] == 3
    assert "id=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" in requested_urls[1]
    cached = waf_detector.get_cached_waf_profile("https://target.local/other")
    assert cached["provider"] == "cloudflare"


def test_waf_detector_identifies_aws_akamai_and_imperva_signatures():
    from core.waf_detector import fingerprint_waf

    aws = fingerprint_waf(
        FakeHTTPResponse("ok", 200, {}),
        FakeHTTPResponse("Request blocked by AWS WAF", 403, {"x-amz-cf-id": "edge"}),
    )
    akamai = fingerprint_waf(
        FakeHTTPResponse("ok", 200, {}),
        FakeHTTPResponse("Access Denied Reference #18", 406, {"Server": "AkamaiGHost"}),
    )
    imperva = fingerprint_waf(
        FakeHTTPResponse("ok", 200, {}),
        FakeHTTPResponse("Request unsuccessful. Incapsula incident ID", 403, {"X-Iinfo": "1-2"}),
    )

    assert aws["provider"] == "aws_waf"
    assert akamai["provider"] == "akamai"
    assert imperva["provider"] == "imperva"
    assert all(result["detected"] for result in [aws, akamai, imperva])


@pytest.mark.asyncio
async def test_scanner_client_applies_cached_waf_throttle_and_safe_encoding(monkeypatch):
    from core import http_client, waf_detector

    waf_detector.clear_waf_profile_cache()
    waf_detector.cache_waf_profile(
        "https://api.local/search",
        {
            "detected": True,
            "provider": "aws_waf",
            "adaptation": {"concurrency_limit": 2, "jitter_range": [1.2, 2.8], "payload_encoding": "double_url"},
        },
    )
    http_client._host_semaphores.clear()
    http_client._host_penalties.clear()
    sleep_calls = []
    seen_urls = []

    async def fake_sleep(value):
        sleep_calls.append(value)

    monkeypatch.setattr(http_client.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(http_client.random, "uniform", lambda low, high: low)

    async def fake_super_request(self, method, url, *args, **kwargs):
        seen_urls.append(str(url))
        return http_client.httpx.Response(200, text="ok", request=http_client.httpx.Request(method, url))

    monkeypatch.setattr(http_client.httpx.AsyncClient, "request", fake_super_request)

    async with http_client.ScannerAsyncClient(jitter_enabled=True) as client:
        response = await client.get("https://api.local/search?q=<script>")

    assert response.status_code == 200
    assert http_client._host_concurrency_limits["api.local"] == 2
    assert http_client._host_penalties["api.local"] >= 1.2
    assert sleep_calls
    assert "%253Cscript%253E" in seen_urls[0]
