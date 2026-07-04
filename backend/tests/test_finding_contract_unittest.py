import unittest

from core.finding_contract import normalize_finding, normalize_findings, normalize_scan_result


class FindingContractTests(unittest.TestCase):
    def test_normalize_finding_removes_exploit_demo_and_marks_real_work(self):
        finding = {
            "type": "Reflected XSS",
            "severity": "High",
            "vector": "URL param 'q'",
            "payload": "<script>alert(1)</script>",
            "evidence": "scratch/evidence/x.txt",
            "exploit_demo": {"code": "offensive demo"},
        }

        normalized = normalize_finding(finding, "https://example.test/?q=1")

        self.assertNotIn("exploit_demo", normalized)
        self.assertTrue(normalized["real_work"])
        self.assertEqual(normalized["verification_state"], "observed")
        self.assertEqual(normalized["confidence"], "medium")
        self.assertEqual(normalized["target_url"], "https://example.test/?q=1")
        self.assertIn("Evidence stored at", normalized["verification_notes"][0])

    def test_normalize_findings_preserves_verified_state(self):
        findings = [
            {
                "type": "SSRF",
                "severity": "Critical",
                "vector": "URL param 'url'",
                "payload": "OAST callback URL",
                "verified": True,
                "evidence": "scratch/evidence/ssrf.txt",
            }
        ]

        normalized = normalize_findings(findings, "https://example.test/?url=x")

        self.assertEqual(normalized[0]["verification_state"], "verified")
        self.assertEqual(normalized[0]["confidence"], "high")

    def test_normalize_scan_result_recomputes_stats_and_module_results(self):
        raw = {
            "total": 99,
            "critical": 99,
            "vulnerabilities": [
                {"type": "A", "severity": "High", "vector": "q", "payload": "x", "exploit_demo": {"code": "demo"}},
                {"type": "B", "severity": "Info", "vector": "h", "payload": "y", "evidence": "e.txt"},
            ],
            "module_results": {
                "test_module": [
                    {"type": "C", "severity": "Critical", "vector": "p", "payload": "z", "exploit_demo": {"code": "demo"}}
                ]
            },
        }

        normalized = normalize_scan_result(raw, "https://example.test")

        self.assertEqual(normalized["total"], 2)
        self.assertEqual(normalized["critical"], 0)
        self.assertEqual(normalized["high"], 1)
        self.assertEqual(normalized["lowInfo"], 1)
        self.assertNotIn("exploit_demo", normalized["vulnerabilities"][0])
        self.assertNotIn("exploit_demo", normalized["module_results"]["test_module"][0])


if __name__ == "__main__":
    unittest.main()
