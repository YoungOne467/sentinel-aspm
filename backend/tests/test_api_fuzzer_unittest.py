import unittest

from modules.api_fuzzer import _dedupe_endpoints, _extract_openapi_endpoints


class ApiFuzzerTests(unittest.TestCase):
    def test_extract_openapi_endpoints_from_paths(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users/{id}": {
                    "get": {"summary": "Get user"},
                    "patch": {"summary": "Update user"},
                    "parameters": [],
                },
                "/api/admin/reports": {
                    "post": {"summary": "Create report"},
                },
            },
        }

        endpoints = _extract_openapi_endpoints("https://example.test", spec)

        paths = {(endpoint["path"], endpoint["method"]) for endpoint in endpoints}
        self.assertIn(("/api/users/1", "GET"), paths)
        self.assertIn(("/api/users/1", "PATCH"), paths)
        self.assertIn(("/api/admin/reports", "POST"), paths)

    def test_dedupe_endpoints_keeps_unique_method_path_pairs(self):
        endpoints = [
            {"path": "/api/users", "method": "GET", "url": "https://example.test/api/users"},
            {"path": "/api/users", "method": "GET", "url": "https://example.test/api/users"},
            {"path": "/api/users", "method": "POST", "url": "https://example.test/api/users"},
        ]

        deduped = _dedupe_endpoints(endpoints)

        self.assertEqual(len(deduped), 2)


if __name__ == "__main__":
    unittest.main()
