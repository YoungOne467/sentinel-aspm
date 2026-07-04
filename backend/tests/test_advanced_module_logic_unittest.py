import unittest

import httpx

from modules.cache_deception import (
    _build_cache_deception_finding,
    _candidate_sensitive_paths,
    _should_report_cache_deception,
)
from modules.cache_poisoning import _build_cache_poisoning_finding, _marker_host, _should_report_cache_poisoning
from modules.graphql_security import _classify_schema_exposure, _summarize_schema


class AdvancedModuleLogicTests(unittest.TestCase):
    def test_cache_poisoning_requires_marker_reflection_and_cache_signal(self):
        baseline = httpx.Response(
            200,
            headers={"Cache-Control": "public, max-age=300", "Vary": "Accept-Encoding"},
            text="<script src='https://static.example.test/app.js'></script>",
        )
        marker_host = _marker_host("unit")
        marker = httpx.Response(
            200,
            headers={"Cache-Control": "public, max-age=300", "Age": "5", "X-Cache": "HIT"},
            text=f"<script src='https://{marker_host}/app.js'></script>",
        )

        decision = _should_report_cache_poisoning(baseline, marker, marker_host, "X-Forwarded-Host")

        self.assertTrue(decision["report"])
        self.assertGreaterEqual(decision["confidence_score"], 5)
        self.assertIn("marker_reflection", decision["signals"])
        self.assertIn("cache_key_missing_x-forwarded-host", decision["signals"])

    def test_cache_poisoning_ignores_baseline_marker_noise(self):
        marker_host = _marker_host("unit")
        baseline = httpx.Response(
            200,
            headers={"Cache-Control": "public, max-age=300"},
            text=f"already contains {marker_host}",
        )
        marker = httpx.Response(
            200,
            headers={"Cache-Control": "public, max-age=300", "X-Cache": "HIT"},
            text=f"already contains {marker_host}",
        )

        decision = _should_report_cache_poisoning(baseline, marker, marker_host, "X-Forwarded-Host")

        self.assertFalse(decision["report"])

    def test_cache_poisoning_finding_contains_decision_metadata(self):
        marker_host = _marker_host("unit")
        response = httpx.Response(200, headers={"Cache-Control": "public, max-age=300"}, text=marker_host)
        decision = {
            "report": True,
            "confidence_score": 6,
            "signals": ["marker_reflection", "explicit_public_cache_control"],
            "cache": {"score": 3, "signals": ["explicit_public_cache_control"]},
            "delta": {"signals": ["marker_reflection"]},
        }

        finding = _build_cache_poisoning_finding(
            "https://example.test/",
            "X-Forwarded-Host",
            marker_host,
            response,
            decision,
        )

        self.assertEqual(finding["confidence"], "high")
        self.assertEqual(finding["verification_state"], "observed")
        self.assertEqual(finding["evidence_details"]["confidence_score"], 6)

    def test_graphql_schema_summary_identifies_sensitive_mutations(self):
        schema = {
            "data": {
                "__schema": {
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Mutation",
                            "fields": [
                                {"name": "resetPassword", "args": [{"name": "token"}]},
                                {"name": "adminCreateUser", "args": [{"name": "role"}]},
                            ],
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [{"name": "currentUser", "args": []}],
                        },
                    ]
                }
            }
        }

        summary = _summarize_schema(schema)
        exposure = _classify_schema_exposure(summary)

        self.assertEqual(summary["mutation_count"], 2)
        self.assertIn("resetPassword", summary["sensitive_fields"])
        self.assertEqual(exposure["severity"], "High")
        self.assertIn("sensitive_mutations_exposed", exposure["signals"])

    def test_cache_deception_candidates_include_current_and_sensitive_paths(self):
        paths = _candidate_sensitive_paths("https://example.test/account/orders?tab=open")

        self.assertIn("/account/orders", paths)
        self.assertIn("/profile", paths)
        self.assertNotIn("/", paths)

    def test_cache_deception_requires_same_content_and_cache_signal(self):
        original = httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text='{"email":"user@example.test","plan":"pro"}',
        )
        deceptive = httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Cache-Control": "public, max-age=600",
                "X-Cache": "HIT",
            },
            text='{"email":"user@example.test","plan":"pro"}',
        )

        decision = _should_report_cache_deception(original, deceptive)

        self.assertTrue(decision["report"])
        self.assertIn("same_body_hash", decision["signals"])
        self.assertIn("explicit_public_cache_control", decision["signals"])

    def test_cache_deception_finding_contains_decision_metadata(self):
        response = httpx.Response(
            200,
            headers={"Cache-Control": "public, max-age=300"},
            text="account data",
        )
        decision = {
            "report": True,
            "confidence_score": 6,
            "signals": ["same_body_hash", "explicit_public_cache_control"],
            "cache": {"score": 3, "signals": ["explicit_public_cache_control"]},
        }

        finding = _build_cache_deception_finding(
            "https://example.test/account",
            "https://example.test/account/aspm-cache.css",
            response,
            decision,
        )

        self.assertEqual(finding["type"], "Web Cache Deception")
        self.assertEqual(finding["confidence"], "high")
        self.assertEqual(finding["evidence_details"]["confidence_score"], 6)


if __name__ == "__main__":
    unittest.main()
