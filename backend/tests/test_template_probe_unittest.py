import unittest

import httpx

from modules.template_probe import _match_signature, _signature_targets


class TemplateProbeTests(unittest.TestCase):
    def test_signature_targets_include_paths_and_surface_nodes(self):
        signature = {"paths": ["/admin", "/debug"]}
        surface_nodes = [{"kind": "page", "url": "https://example.test/swagger"}, {"kind": "api", "url": "https://example.test/api/debug"}]

        targets = _signature_targets("https://example.test", signature, surface_nodes)

        self.assertIn("https://example.test/admin", targets)
        self.assertIn("https://example.test/debug", targets)
        self.assertIn("https://example.test/swagger", targets)
        self.assertIn("https://example.test/api/debug", targets)

    def test_match_signature_requires_status_and_body_markers(self):
        response = httpx.Response(200, text='{"swagger":"2.0","paths":{}}', headers={"content-type": "application/json"})
        signature = {
            "match": {
                "status": [200],
                "body_contains": ["swagger", "paths"],
                "headers": {"content-type": "json"},
            }
        }

        matched, reasons = _match_signature(signature, response)

        self.assertTrue(matched)
        self.assertIn("body contains 'swagger'", reasons)
        self.assertIn("header content-type contains 'json'", reasons)


if __name__ == "__main__":
    unittest.main()
