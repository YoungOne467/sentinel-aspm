import unittest

from core.probe_scheduler import build_probe_plan
from core.surface_graph import ScanSurfaceGraph


class ProbeSchedulerTests(unittest.TestCase):
    def test_endpoint_aware_modules_receive_surface_targets_first(self):
        graph = ScanSurfaceGraph("https://example.test")
        graph.add_node(kind="api", url="https://example.test/api/users/1", classification="user_data_route")
        graph.add_node(kind="page", url="https://example.test/admin", classification="high_value_route")

        plan = build_probe_plan(
            ["Security Header Audit", "API Endpoint Fuzzing", "GraphQL Security", "Web Cache Poisoning"],
            graph,
            intensity="maximum",
        )

        ordered_names = [task.module_name for task in plan]
        self.assertLess(ordered_names.index("API Endpoint Fuzzing"), ordered_names.index("Security Header Audit"))
        self.assertGreaterEqual(len(plan[0].targets), 1)

    def test_deep_modules_are_prioritized_at_maximum_depth(self):
        graph = ScanSurfaceGraph("https://example.test")

        plan = build_probe_plan(
            ["HTTP Request Smuggling", "Security Header Audit", "Blind SQLi Timing"],
            graph,
            intensity="normal",
            penetration_depth="maximum",
        )

        ordered_names = [task.module_name for task in plan]
        self.assertLess(ordered_names.index("Blind SQLi Timing"), ordered_names.index("Security Header Audit"))


if __name__ == "__main__":
    unittest.main()
