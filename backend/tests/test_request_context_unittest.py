import unittest

from core.request_context import get_scan_context_headers, sanitize_scan_headers, scan_header_context


class RequestContextTests(unittest.TestCase):
    def test_sanitize_scan_headers_preserves_auth_and_cookie(self):
        headers = sanitize_scan_headers({
            "Authorization": "Bearer abc",
            "Cookie": "sid=123",
            "Connection": "close",
            "Bad\nName": "x",
            "X-Test": "hello\r\nbad",
        })

        self.assertEqual(headers["Authorization"], "Bearer abc")
        self.assertEqual(headers["Cookie"], "sid=123")
        self.assertNotIn("Connection", headers)
        self.assertNotIn("Bad\nName", headers)
        self.assertEqual(headers["X-Test"], "hellobad")

    def test_scan_header_context_is_scoped(self):
        self.assertEqual(get_scan_context_headers(), {})

        with scan_header_context({"Authorization": "Bearer scoped"}):
            self.assertEqual(get_scan_context_headers()["Authorization"], "Bearer scoped")

        self.assertEqual(get_scan_context_headers(), {})


if __name__ == "__main__":
    unittest.main()
