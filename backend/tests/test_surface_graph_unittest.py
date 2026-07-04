import unittest

from core.surface_graph import ScanSurfaceGraph, build_proof_chain


class SurfaceGraphTests(unittest.TestCase):
    def test_graph_dedupes_and_enforces_scope(self):
        graph = ScanSurfaceGraph(
            "https://example.test/app",
            scope={
                "allowed_hosts": ["example.test"],
                "allowed_path_prefixes": ["/app", "/api"],
                "excluded_paths": ["/app/logout"],
            },
        )

        first_id = graph.add_node(
            kind="page",
            url="https://example.test/app/admin",
            classification="high_value_route",
            source="crawler",
        )
        second_id = graph.add_node(
            kind="page",
            url="https://example.test/app/admin#ignored",
            classification="high_value_route",
            source="crawler",
        )
        foreign_id = graph.add_node(kind="page", url="https://evil.test/app/admin")
        excluded_id = graph.add_node(kind="page", url="https://example.test/app/logout")

        self.assertEqual(first_id, second_id)
        self.assertIsNone(foreign_id)
        self.assertIsNone(excluded_id)

        exported = graph.to_dict()
        self.assertEqual(exported["node_count"], 1)
        self.assertEqual(exported["nodes"][0]["classification"], "high_value_route")

    def test_graph_merges_html_surface_into_typed_nodes(self):
        graph = ScanSurfaceGraph("https://example.test")
        graph.merge_surface(
            "https://example.test/account",
            {
                "links": ["https://example.test/account/settings"],
                "scripts": ["https://example.test/static/app.js"],
                "forms": [{"action": "https://example.test/api/profile", "method": "POST", "inputs": ["email", "csrf"]}],
                "api_candidates": ["https://example.test/api/profile"],
            },
        )

        kinds = {node["kind"] for node in graph.to_dict()["nodes"]}
        self.assertIn("page", kinds)
        self.assertIn("script", kinds)
        self.assertIn("form", kinds)
        self.assertIn("api", kinds)

        api_targets = graph.targets(kinds={"api"})
        self.assertEqual(len(api_targets), 1)
        self.assertEqual(api_targets[0]["url"], "https://example.test/api/profile")

    def test_build_proof_chain_records_baseline_and_mutation(self):
        proof = build_proof_chain(
            baseline={"method": "GET", "url": "https://example.test/api/user/1", "status_code": 403, "body_fingerprint": "a"},
            mutation={"method": "GET", "url": "https://example.test/api/user/2", "status_code": 200, "body_fingerprint": "b"},
            verdict="secondary identity received object data",
        )

        self.assertEqual([step["phase"] for step in proof], ["baseline", "mutation", "verdict"])
        self.assertEqual(proof[2]["summary"], "secondary identity received object data")


if __name__ == "__main__":
    unittest.main()
