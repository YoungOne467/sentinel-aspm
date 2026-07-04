import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.surface_graph import ScanSurfaceGraph
from modules.api_resource_consumption import run_api_resource_consumption_scan
from modules.authorization_matrix import run_authorization_matrix_scan
from modules.client_exposure import run_client_exposure_scan


class _ThreatTargetHandler(BaseHTTPRequestHandler):
    def _send(self, status, body, content_type="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return

    def do_GET(self):
        if self.path.startswith("/admin"):
            self._send(200, '{"admin":true,"users":[1,2]}', "application/json")
            return
        if self.path.startswith("/api/items"):
            limit = 1
            if "limit=10000" in self.path or "limit=5000" in self.path:
                limit = 5000
            body = json.dumps({"items": [{"id": i, "email": f"user{i}@example.test"} for i in range(limit)]})
            self._send(200, body, "application/json")
            return
        if self.path == "/static/app.js":
            self._send(
                200,
                "localStorage.setItem('token', jwt); window.postMessage({token: jwt}, '*');\n//# sourceMappingURL=app.js.map",
                "application/javascript",
            )
            return
        if self.path == "/static/app.js.map":
            self._send(200, '{"version":3,"sourcesContent":["const apiKey=\\"live-key\\";"]}', "application/json")
            return
        self._send(404, "not found")


class ThreatModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _ThreatTargetHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)
        cls.server.server_close()

    async def _broadcast(self, _message):
        return None

    def _graph(self):
        graph = ScanSurfaceGraph(self.base_url)
        graph.add_node("api", f"{self.base_url}/admin", classification="high_value_route")
        graph.add_node("api", f"{self.base_url}/api/items", params=["limit"], classification="user_data_route")
        graph.add_node("script", f"{self.base_url}/static/app.js", classification="client_code")
        return graph

    def test_authorization_matrix_flags_admin_route_reachable_to_primary(self):
        findings = asyncio.run(run_authorization_matrix_scan(
            self.base_url,
            "normal",
            self._broadcast,
            surface_graph=self._graph(),
            auth_profiles={"anonymous": {}, "primary": {"Authorization": "Bearer user"}},
        ))

        self.assertTrue(any(finding["type"] == "Broken Function Level Authorization" for finding in findings))

    def test_resource_consumption_flags_unbounded_limit_parameter(self):
        findings = asyncio.run(run_api_resource_consumption_scan(
            self.base_url,
            "normal",
            self._broadcast,
            surface_graph=self._graph(),
        ))

        self.assertTrue(any(finding["type"] == "Unrestricted API Resource Consumption" for finding in findings))

    def test_client_exposure_flags_source_map_and_token_patterns(self):
        findings = asyncio.run(run_client_exposure_scan(
            self.base_url,
            "normal",
            self._broadcast,
            surface_graph=self._graph(),
        ))

        finding_types = {finding["type"] for finding in findings}
        self.assertIn("Exposed JavaScript Source Map", finding_types)
        self.assertIn("Client-Side Secret or Token Handling Exposure", finding_types)


if __name__ == "__main__":
    unittest.main()
