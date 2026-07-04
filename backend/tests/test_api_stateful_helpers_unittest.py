import unittest

import httpx

from modules.api_fuzzer import _classify_parameter, _identity_delta_finding


class ApiStatefulHelperTests(unittest.TestCase):
    def test_classify_parameter_identifies_sensitive_object_identifiers(self):
        self.assertEqual(_classify_parameter("accountId"), "object_id")
        self.assertEqual(_classify_parameter("role"), "privilege")
        self.assertEqual(_classify_parameter("email"), "personal_data")

    def test_identity_delta_finding_builds_bola_proof_chain(self):
        primary = httpx.Response(200, json={"id": 1, "email": "a@example.test"})
        secondary = httpx.Response(200, json={"id": 1, "email": "a@example.test"})
        finding = _identity_delta_finding(
            endpoint={"path": "/api/users/1", "url": "https://example.test/api/users/1", "method": "GET", "surface_node": "node-1"},
            baseline_profile="primary",
            mutation_profile="secondary",
            baseline_response=primary,
            mutation_response=secondary,
        )

        self.assertEqual(finding["type"], "Broken Object Level Authorization (BOLA/IDOR)")
        self.assertEqual(finding["affected_identity"], "secondary")
        self.assertEqual(finding["surface_node"], "node-1")
        self.assertGreaterEqual(finding["confidence_score"], 0.8)
        self.assertEqual([step["phase"] for step in finding["proof_chain"]], ["baseline", "mutation", "verdict"])


if __name__ == "__main__":
    unittest.main()
