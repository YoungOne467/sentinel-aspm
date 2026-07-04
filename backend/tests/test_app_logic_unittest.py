import os
import unittest

from pydantic import ValidationError

from core.target_policy import TargetPolicyError, normalize_target_url, validate_scan_target


class AppLogicTests(unittest.TestCase):
    def test_normalize_target_requires_http_scheme(self):
        self.assertEqual(normalize_target_url("example.com"), "https://example.com")
        self.assertEqual(normalize_target_url(" http://example.com/a "), "http://example.com/a")

        with self.assertRaises(TargetPolicyError):
            normalize_target_url("ftp://example.com")

    def test_private_targets_are_blocked_by_default(self):
        previous = os.environ.pop("ASPM_ALLOW_PRIVATE_TARGETS", None)
        try:
            with self.assertRaises(TargetPolicyError):
                validate_scan_target("http://127.0.0.1:8000")
        finally:
            if previous is not None:
                os.environ["ASPM_ALLOW_PRIVATE_TARGETS"] = previous

    def test_private_targets_can_be_enabled_for_lab_use(self):
        previous = os.environ.get("ASPM_ALLOW_PRIVATE_TARGETS")
        os.environ["ASPM_ALLOW_PRIVATE_TARGETS"] = "1"
        try:
            self.assertEqual(validate_scan_target("http://127.0.0.1:8000"), "http://127.0.0.1:8000")
        finally:
            if previous is None:
                os.environ.pop("ASPM_ALLOW_PRIVATE_TARGETS", None)
            else:
                os.environ["ASPM_ALLOW_PRIVATE_TARGETS"] = previous

    def test_scan_request_rejects_unknown_intensity(self):
        from main import ScanRequest

        with self.assertRaises(ValidationError):
            ScanRequest(url="https://example.com", intensity="maximum")

    def test_scan_request_accepts_sanitized_scan_headers(self):
        from main import ScanRequest

        request = ScanRequest(
            url="https://example.com",
            intensity="normal",
            scan_headers={"Authorization": "Bearer token", "Connection": "close"},
        )

        self.assertEqual(request.scan_headers, {"Authorization": "Bearer token"})

    def test_scan_request_accepts_stateful_penetration_options(self):
        from main import ScanRequest

        request = ScanRequest(
            url="https://example.com",
            intensity="aggressive",
            auth_profiles={
                "primary": {"headers": {"Authorization": "Bearer primary"}},
                "secondary": {"Cookie": "sid=secondary"},
            },
            openapi_url="https://example.com/openapi.json",
            scope={"allowed_hosts": ["example.com"], "allowed_path_prefixes": ["/api"], "excluded_paths": ["/logout"]},
            penetration_depth="maximum",
            state_changing=True,
        )

        self.assertEqual(request.auth_profiles["primary"], {"Authorization": "Bearer primary"})
        self.assertEqual(request.auth_profiles["secondary"], {"Cookie": "sid=secondary"})
        self.assertEqual(request.openapi_url, "https://example.com/openapi.json")
        self.assertEqual(request.scope["allowed_hosts"], ["example.com"])
        self.assertEqual(request.penetration_depth, "maximum")
        self.assertTrue(request.state_changing)

    def test_deep_exfiltration_action_is_allowed(self):
        from main import normalize_exploit_action

        self.assertEqual(normalize_exploit_action("Deep Exfiltration"), "deep exfiltration")

    def test_global_headers_do_not_spoof_source_identity(self):
        from main import _get_global_request_headers

        headers = _get_global_request_headers()

        self.assertIn("User-Agent", headers)
        self.assertNotIn("X-Forwarded-For", headers)
        self.assertNotIn("True-Client-IP", headers)
        self.assertNotIn("X-Host", headers)


if __name__ == "__main__":
    unittest.main()
