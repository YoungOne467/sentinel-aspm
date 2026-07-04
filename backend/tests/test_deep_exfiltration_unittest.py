import unittest

import httpx

from agents.deep_exfiltration import assess_deep_exfiltration
from agents.exploit_tester import AutonomousExploiter


async def _noop_broadcast(_message):
    return None


class DeepExfiltrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        exploiter = getattr(self, "exploiter", None)
        if exploiter is not None:
            await exploiter.client.aclose()
            await exploiter.oast_client.close()

    def _make_exploiter(self, **overrides):
        params = {
            "target_url": "https://example.test/search",
            "vuln_type": "sql injection",
            "base_payload": "' OR '1'='1",
            "vector": "Query: q",
            "broadcast_cb": _noop_broadcast,
            "post_action": "Deep Exfiltration",
            "use_ai": False,
        }
        params.update(overrides)
        self.exploiter = AutonomousExploiter(**params)
        return self.exploiter

    def test_assessor_detects_multiple_sensitive_data_classes(self):
        response = httpx.Response(
            200,
            text=(
                "root:x:0:0:root:/root:/bin/bash\n"
                "DB_PASSWORD=super-secret\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "user email: admin@example.test\n"
            ),
        )

        assessment = assess_deep_exfiltration("lfi", "../../../../etc/passwd", response)

        labels = {item["label"] for item in assessment["data_classes"]}
        self.assertIn("filesystem_identity_file", labels)
        self.assertIn("application_secret", labels)
        self.assertIn("cloud_access_key", labels)
        self.assertIn("personal_data", labels)
        self.assertEqual(assessment["exposure_level"], "critical")
        self.assertGreaterEqual(assessment["exposure_score"], 90)
        self.assertEqual(assessment["blast_radius"]["level"], "host_or_cloud_compromise")

    async def test_deep_exfiltration_mode_builds_live_exposure_evidence(self):
        exploiter = self._make_exploiter()
        response = httpx.Response(
            200,
            text="SQL syntax error near SELECT current_user; email=admin@example.test; JWT_SECRET=abc123",
        )

        evidence = await exploiter._gather_evidence("' OR '1'='1", response)

        self.assertEqual(evidence["mode"], "Deep Exfiltration")
        self.assertEqual(evidence["summary"], "Deep exfiltration impact assessment completed.")
        self.assertGreaterEqual(evidence["data"]["exposure_score"], 60)
        self.assertIn("data_classes", evidence["data"])
        self.assertIn("blast_radius", evidence["data"])
        self.assertIn("impact_paths", evidence["data"])

    def test_deep_exfiltration_action_is_recognized(self):
        exploiter = self._make_exploiter()

        self.assertTrue(exploiter._is_deep_exfiltration_mode())
        self.assertTrue(exploiter._allows_active_evidence())

    def test_assessor_detects_canaries_and_generates_priority_actions(self):
        response = httpx.Response(
            200,
            text=(
                "ASPM_CANARY_CUSTOMER_ID=seeded-customer-001\n"
                "ASPM_CANARY_SECRET=prelaunch-secret-proof\n"
                "JWT_SECRET=abc123\n"
                "email=owner@example.test\n"
            ),
        )

        assessment = assess_deep_exfiltration("idor", "customer=1", response)

        labels = {item["label"] for item in assessment["data_classes"]}
        self.assertIn("aspm_canary", labels)
        self.assertTrue(assessment["canary_hits"])
        self.assertGreaterEqual(assessment["sensitive_density_per_kb"], 1)
        self.assertGreaterEqual(len(assessment["priority_actions"]), 3)
        self.assertTrue(any(path["name"] == "seeded_canary_exposure" for path in assessment["impact_paths"]))

    def test_assessor_returns_none_level_for_clean_response(self):
        response = httpx.Response(200, text="<html><h1>Welcome</h1></html>")

        assessment = assess_deep_exfiltration("xss", "<script>alert(1)</script>", response)

        self.assertEqual(assessment["exposure_score"], 0)
        self.assertEqual(assessment["exposure_level"], "none")
        self.assertEqual(assessment["blast_radius"]["level"], "none")
        self.assertEqual(assessment["data_classes"], [])


if __name__ == "__main__":
    unittest.main()
