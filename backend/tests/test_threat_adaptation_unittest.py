import unittest

from core.surface_graph import ScanSurfaceGraph
from core.threat_adaptation import build_adaptive_scan_summary, module_priority_delta


class ThreatAdaptationTests(unittest.TestCase):
    def test_summary_prioritizes_admin_api_and_authz_modules(self):
        graph = ScanSurfaceGraph("https://example.test")
        graph.add_node("api", "https://example.test/api/admin/users/1", params=["id"], classification="high_value_route")
        graph.add_node("script", "https://example.test/static/app.js", classification="client_code")

        summary = build_adaptive_scan_summary(
            graph,
            findings=[],
            auth_profiles={"anonymous": {}, "primary": {"Authorization": "Bearer a"}, "secondary": {"Authorization": "Bearer b"}},
            intensity="aggressive",
        )

        self.assertIn("authorization_matrix", summary["recommended_modules"])
        self.assertIn("api_resource_consumption", summary["recommended_modules"])
        self.assertIn("client_exposure", summary["recommended_modules"])
        self.assertGreater(summary["surface_heat"], 0)

    def test_module_priority_delta_promotes_recommended_modules(self):
        summary = {"recommended_modules": ["authorization_matrix", "client_exposure"]}

        self.assertLess(module_priority_delta("Authorization Matrix", summary), 0)
        self.assertLess(module_priority_delta("Client Exposure", summary), 0)
        self.assertEqual(module_priority_delta("Security Header Audit", summary), 0)


if __name__ == "__main__":
    unittest.main()
