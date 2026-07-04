import unittest

from core.finding_contract import normalize_finding


class FindingProofContractTests(unittest.TestCase):
    def test_normalize_finding_preserves_proof_chain_fields(self):
        finding = normalize_finding(
            {
                "type": "Proof Finding",
                "severity": "High",
                "proof_chain": [{"phase": "baseline", "status_code": 403}],
                "affected_identity": "secondary",
                "surface_node": "node-1",
                "confidence_score": 0.91,
                "replay": {"method": "GET", "url": "https://example.test/api/users/1"},
            },
            "https://example.test",
        )

        self.assertEqual(finding["proof_chain"][0]["phase"], "baseline")
        self.assertEqual(finding["affected_identity"], "secondary")
        self.assertEqual(finding["surface_node"], "node-1")
        self.assertEqual(finding["confidence_score"], 0.91)
        self.assertEqual(finding["replay"]["method"], "GET")

    def test_normalize_finding_adds_empty_proof_defaults(self):
        finding = normalize_finding({"type": "Candidate", "severity": "Low"}, "https://example.test")

        self.assertEqual(finding["proof_chain"], [])
        self.assertEqual(finding["affected_identity"], "unknown")
        self.assertIsNone(finding["surface_node"])
        self.assertIn("method", finding["replay"])


if __name__ == "__main__":
    unittest.main()
