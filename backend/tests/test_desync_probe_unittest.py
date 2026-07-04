import unittest

from modules.http_desync_advanced import _build_raw_request, _desync_signal


class DesyncProbeTests(unittest.TestCase):
    def test_raw_cl0_probe_contains_queued_request(self):
        request = _build_raw_request("example.test", "/", "cl0").decode("ascii")

        self.assertIn("Content-Length: 0", request)
        self.assertIn("GET /aspm-desync-probe HTTP/1.1", request)

    def test_desync_signal_detects_multiple_http_responses(self):
        report, signals = _desync_signal({"response": b"HTTP/1.1 200 OK\r\n\r\noneHTTP/1.1 404 Not Found\r\n\r\ntwo"})

        self.assertTrue(report)
        self.assertIn("multiple_http_responses", signals)


if __name__ == "__main__":
    unittest.main()
