import unittest

from core.auth_profiles import auth_profile_context, get_auth_profile_headers, sanitize_auth_profiles
from core.request_context import get_scan_context_headers


class AuthProfilesTests(unittest.TestCase):
    def test_sanitize_profiles_accepts_mapping_and_legacy_headers(self):
        profiles = sanitize_auth_profiles(
            {
                "primary": {"headers": {"Authorization": "Bearer primary", "Host": "ignored.test"}},
                "secondary": {"Cookie": "sid=secondary", "X-Tenant": "blue"},
            },
            legacy_headers={"Authorization": "Bearer legacy"},
        )

        self.assertEqual(profiles["anonymous"], {})
        self.assertEqual(profiles["primary"], {"Authorization": "Bearer primary"})
        self.assertEqual(profiles["secondary"], {"Cookie": "sid=secondary", "X-Tenant": "blue"})

    def test_legacy_scan_headers_become_primary_profile(self):
        profiles = sanitize_auth_profiles(None, legacy_headers={"Authorization": "Bearer token"})

        self.assertEqual(profiles["anonymous"], {})
        self.assertEqual(profiles["primary"], {"Authorization": "Bearer token"})

    def test_profile_context_applies_headers_to_request_context(self):
        profiles = sanitize_auth_profiles({"primary": {"Authorization": "Bearer token"}})

        with auth_profile_context(profiles, "primary"):
            self.assertEqual(get_scan_context_headers(), {"Authorization": "Bearer token"})
            self.assertEqual(get_auth_profile_headers(profiles, "primary"), {"Authorization": "Bearer token"})

        self.assertEqual(get_scan_context_headers(), {})


if __name__ == "__main__":
    unittest.main()
