import unittest

from core.surface_mapper import extract_surface_from_html, normalize_discovered_url


class SurfaceMapperTests(unittest.TestCase):
    def test_extracts_links_forms_scripts_and_api_candidates(self):
        html = """
        <html>
          <a href="/account">Account</a>
          <a href="https://other.example.test/offsite">Offsite</a>
          <form action="/api/profile/1" method="post">
            <input name="email">
            <input name="password" type="password">
          </form>
          <script src="/assets/app.js"></script>
          <script>
            fetch('/api/orders/1');
            axios.post("/graphql", {});
          </script>
        </html>
        """

        surface = extract_surface_from_html("https://example.test/start", html)

        self.assertIn("https://example.test/account", surface["links"])
        self.assertIn("https://example.test/assets/app.js", surface["scripts"])
        self.assertIn("https://example.test/api/orders/1", surface["api_candidates"])
        self.assertIn("https://example.test/graphql", surface["api_candidates"])
        self.assertEqual(surface["forms"][0]["method"], "POST")
        self.assertEqual(surface["forms"][0]["inputs"], ["email", "password"])

    def test_normalize_discovered_url_rejects_cross_origin_and_fragments(self):
        self.assertEqual(
            normalize_discovered_url("https://example.test/a#frag", "/b?x=1#top"),
            "https://example.test/b?x=1",
        )
        self.assertIsNone(
            normalize_discovered_url("https://example.test/a", "https://evil.example.test/b"),
        )


if __name__ == "__main__":
    unittest.main()
