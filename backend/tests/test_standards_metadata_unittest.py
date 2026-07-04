import unittest

from core.finding_contract import normalize_finding


class StandardsMetadataTests(unittest.TestCase):
    def test_sqli_findings_include_wstg_cwe_and_reference_metadata(self):
        finding = {
            "type": "SQL Injection",
            "severity": "High",
            "vector": "Query: id",
            "payload": "' OR '1'='1",
        }

        normalized = normalize_finding(finding, "https://example.com")

        self.assertEqual(normalized["wstg"], "WSTG-INPV-05")
        self.assertIn("CWE-89", normalized["cwe"])
        self.assertTrue(
            any("Testing_for_SQL_Injection" in ref["url"] for ref in normalized["references"])
        )

    def test_ssrf_module_findings_include_owasp_metadata(self):
        finding = {
            "type": "Server-Side Request Forgery",
            "severity": "High",
            "module": "ssrf_oast",
            "vector": "URL parameter",
            "payload": "http://example.test",
        }

        normalized = normalize_finding(finding, "https://example.com")

        self.assertEqual(normalized["wstg"], "WSTG-INPV-19")
        self.assertIn("CWE-918", normalized["cwe"])
        self.assertEqual(normalized["owasp_category"], "Server-Side Request Forgery")

    def test_cache_poisoning_findings_include_cache_metadata(self):
        finding = {
            "type": "Web Cache Poisoning",
            "severity": "High",
            "module": "cache_poisoning",
            "vector": "X-Forwarded-Host",
        }

        normalized = normalize_finding(finding, "https://example.com")

        self.assertEqual(normalized["wstg"], "WSTG-CONF")
        self.assertIn("CWE-444", normalized["cwe"])
        self.assertEqual(normalized["owasp_category"], "Web Cache Poisoning")

    def test_graphql_findings_include_api_metadata(self):
        finding = {
            "type": "GraphQL Introspection Enabled",
            "severity": "High",
            "module": "graphql_security",
            "vector": "POST Body",
        }

        normalized = normalize_finding(finding, "https://example.com")

        self.assertEqual(normalized["wstg"], "WSTG-APIT-01")
        self.assertIn("CWE-200", normalized["cwe"])
        self.assertEqual(normalized["owasp_category"], "API Security Misconfiguration")


if __name__ == "__main__":
    unittest.main()
