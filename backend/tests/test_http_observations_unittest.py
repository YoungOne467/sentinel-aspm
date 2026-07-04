import unittest

import httpx

from core.http_observations import (
    cache_indicators,
    fingerprint_response,
    header_value,
    response_delta,
)


class HttpObservationTests(unittest.TestCase):
    def test_cache_indicators_score_real_cache_headers(self):
        response = httpx.Response(
            200,
            headers={
                "Cache-Control": "public, max-age=600",
                "Age": "42",
                "X-Cache": "HIT",
                "Vary": "Accept-Encoding",
            },
            text="cached body",
        )

        indicators = cache_indicators(response, varied_header="X-Forwarded-Host")

        self.assertGreaterEqual(indicators["score"], 4)
        self.assertIn("explicit_public_cache_control", indicators["signals"])
        self.assertIn("cache_age_present", indicators["signals"])
        self.assertIn("cache_key_missing_x-forwarded-host", indicators["signals"])

    def test_response_delta_catches_marker_only_reflection(self):
        baseline = httpx.Response(200, text="<a href='https://example.test/app.js'>")
        marker = httpx.Response(200, text="<a href='https://aspm-abc123.invalid/app.js'>")

        delta = response_delta(
            fingerprint_response(baseline),
            fingerprint_response(marker),
            marker="aspm-abc123.invalid",
        )

        self.assertTrue(delta["marker_reflected"])
        self.assertIn("marker_reflection", delta["signals"])
        self.assertIn("body_hash_changed", delta["signals"])

    def test_header_value_is_case_insensitive(self):
        response = httpx.Response(200, headers={"Cache-Status": "cdn; hit"})

        self.assertEqual(header_value(response, "cache-status"), "cdn; hit")


if __name__ == "__main__":
    unittest.main()
