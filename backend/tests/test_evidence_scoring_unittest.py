import unittest

import httpx

from agents.exploit_tester import AutonomousExploiter


async def _noop_broadcast(_message):
    return None


class EvidenceScoringTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        exploiter = getattr(self, "exploiter", None)
        if exploiter is not None:
            await exploiter.client.aclose()
            await exploiter.oast_client.close()

    def _make_exploiter(self, **overrides):
        params = {
            "target_url": "https://example.test/app",
            "vuln_type": "unknown",
            "base_payload": "test",
            "vector": "Query: q",
            "broadcast_cb": _noop_broadcast,
            "post_action": "Verify Only",
            "use_ai": False,
        }
        params.update(overrides)
        self.exploiter = AutonomousExploiter(**params)
        return self.exploiter

    async def test_generic_200_response_is_not_success_without_strong_signal(self):
        exploiter = self._make_exploiter(vuln_type="business logic")
        response = httpx.Response(200, text="<html><h1>Welcome</h1><p>Static marketing page.</p></html>")

        self.assertFalse(await exploiter._check_success("1", response))
        self.assertLess(exploiter.last_evidence_score["score"], 0.65)

    async def test_oast_callback_sets_high_evidence_score(self):
        exploiter = self._make_exploiter(vuln_type="ssrf", base_payload="http://OAST_ID/")

        async def _seen_callback():
            return True

        exploiter.oast_client.poll_interactions = _seen_callback
        response = httpx.Response(200, text="queued")

        self.assertTrue(await exploiter._check_success("http://abc.requestrepo.com/", response))
        self.assertEqual(exploiter.last_evidence_score["level"], "high")
        self.assertIn("oast_callback", exploiter.last_evidence_score["signals"])


if __name__ == "__main__":
    unittest.main()
