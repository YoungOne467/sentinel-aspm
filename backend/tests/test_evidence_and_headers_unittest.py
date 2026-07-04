import unittest

from modules.header_audit import _check_csp_quality


class EvidenceAndHeaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_csp_quality_distinguishes_script_inline_from_style_inline(self):
        csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'"

        issues = await _check_csp_quality(csp, lambda _message: None)

        self.assertFalse(any("unsafe-inline scripts" in issue for issue in issues))

    async def test_csp_quality_flags_missing_object_src_and_base_uri(self):
        csp = "default-src 'self'; script-src 'self'"

        issues = await _check_csp_quality(csp, lambda _message: None)

        self.assertTrue(any("object-src" in issue for issue in issues))
        self.assertTrue(any("base-uri" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
