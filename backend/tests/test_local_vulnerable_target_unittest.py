import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from modules.api_fuzzer import run_api_fuzz
from modules.file_upload import run_file_upload_scan
from modules.graphql_security import run_graphql_scan


class _VulnerableTargetHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status, text):
        body = text.encode()
        self.send_response(status)
        self.send_header("content-type", "text/html")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return

    def do_GET(self):
        if self.path == "/openapi.json":
            self._send_json(200, {
                "openapi": "3.0.0",
                "paths": {
                    "/api/users/{id}": {
                        "get": {
                            "operationId": "getUser",
                            "parameters": [{"name": "id", "in": "path"}],
                        }
                    }
                },
            })
            return
        if self.path.startswith("/api/users/"):
            self._send_json(200, {"id": 1, "email": "owner@example.test", "token": "dev-token", "role": "admin"})
            return
        if self.path == "/graphql":
            self._send_text(200, "GraphQL")
            return
        self._send_text(404, "not found")

    def do_OPTIONS(self):
        if self.path == "/api/upload":
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("content-length", "0") or "0")
        raw_body = self.rfile.read(length)
        if self.path == "/graphql":
            try:
                body = json.loads(raw_body.decode() or "{}")
            except Exception:
                body = {}
            if isinstance(body, list):
                self._send_json(200, [{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}])
                return
            if "__schema" in str(body):
                self._send_json(200, {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "subscriptionType": None,
                            "directives": [],
                            "types": [
                                {"name": "Query", "fields": [{"name": "user", "args": [{"name": "id"}]}]},
                                {"name": "Mutation", "fields": [{"name": "resetPassword", "args": [{"name": "token"}]}]},
                            ],
                        }
                    }
                })
                return
            self._send_json(200, {"data": {"__typename": "Query"}})
            return
        if self.path == "/api/upload":
            content_disposition = self.headers.get("content-type", "")
            if "multipart/form-data" in content_disposition:
                # Naively try to find the filename in the body.
                import re
                try:
                    # In a real app we'd parse multipart, here we just regex the raw body
                    raw_str = raw_body.decode(errors='ignore')
                    m = re.search(r'filename="([^"]+)"', raw_str)
                    filename = m.group(1) if m else "test.php"
                except Exception:
                    filename = "test.php"
                self._send_json(201, {"success": True, "file": filename})
            else:
                self._send_json(201, {"success": True, "file": "test.php"})
            return
        self._send_text(404, "not found")


class LocalVulnerableTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableTargetHandler)
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

    def test_api_fuzzer_finds_bola_and_excessive_data_on_local_target(self):
        findings = asyncio.run(run_api_fuzz(
            self.base_url,
            "normal",
            self._broadcast,
            auth_profiles={
                "primary": {"Authorization": "Bearer primary"},
                "secondary": {"Authorization": "Bearer secondary"},
            },
        ))

        finding_types = {finding["type"] for finding in findings}
        self.assertIn("Broken Object Level Authorization (BOLA/IDOR)", finding_types)
        self.assertIn("Excessive API Data Exposure", finding_types)

    def test_graphql_module_finds_introspection_and_batching_on_local_target(self):
        findings = asyncio.run(run_graphql_scan(self.base_url, "normal", self._broadcast))

        finding_types = {finding["type"] for finding in findings}
        self.assertIn("GraphQL Introspection Enabled", finding_types)
        self.assertIn("GraphQL Batch Operations Enabled", finding_types)

    def test_file_upload_module_finds_unsafe_upload_on_local_target(self):
        findings = asyncio.run(run_file_upload_scan(self.base_url, "normal", self._broadcast))

        self.assertTrue(any(finding["type"] == "Unsafe File Upload" for finding in findings))


if __name__ == "__main__":
    unittest.main()
