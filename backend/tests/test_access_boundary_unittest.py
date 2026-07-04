import unittest

import httpx

from agents.access_boundary import build_readonly_command_payload
from agents.exploit_tester import AutonomousExploiter


async def _noop_broadcast(_message):
    return None


class AccessBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        exploiter = getattr(self, "exploiter", None)
        if exploiter is not None:
            await exploiter.client.aclose()
            await exploiter.oast_client.close()

    def _make_exploiter(self, **overrides):
        params = {
            "target_url": "https://example.test/admin",
            "vuln_type": "idor",
            "base_payload": "2",
            "vector": "Query: account_id",
            "broadcast_cb": _noop_broadcast,
            "post_action": "Aggressive Proof of Access",
            "use_ai": False,
            "surface_node": "route-admin",
            "auth_profile": "secondary",
        }
        params.update(overrides)
        self.exploiter = AutonomousExploiter(**params)
        return self.exploiter

    def test_aggressive_proof_action_is_allowed(self):
        from main import normalize_exploit_action

        self.assertEqual(
            normalize_exploit_action("Aggressive Proof of Access"),
            "aggressive proof of access",
        )
        self.assertEqual(normalize_exploit_action("Proof Of Access"), "aggressive proof of access")
        self.assertEqual(normalize_exploit_action("Access Mode"), "access mode")

    async def test_proof_of_access_evidence_stops_at_operator_handoff(self):
        exploiter = self._make_exploiter()

        class PostAccessStrategyShouldNotRun:
            async def gather_evidence(self, _payload, _response):
                raise AssertionError("post-access strategy requests should not run")

        exploiter.strategy = PostAccessStrategyShouldNotRun()
        response = httpx.Response(
            200,
            text="admin dashboard email=owner@example.test ASPM_CANARY_SECRET=seeded-secret-001",
        )

        evidence = await exploiter._gather_evidence("account_id=2", response)

        self.assertEqual(evidence["mode"], "Aggressive Proof of Access")
        boundary = evidence["data"]["access_boundary"]
        self.assertTrue(boundary["access_proven"])
        self.assertEqual(boundary["state"], "operator_handoff")
        self.assertEqual(boundary["stop_reason"], "access_proof_reached")
        self.assertEqual(boundary["next_owner"], "operator")
        self.assertEqual(boundary["auth_profile"], "secondary")
        self.assertEqual(boundary["surface_node"], "route-admin")

    async def test_access_mode_exposes_confirmed_operator_actions(self):
        exploiter = self._make_exploiter(
            vuln_type="command injection",
            base_payload="; id",
            vector="Query: cmd",
            post_action="Access Mode",
        )
        response = httpx.Response(200, text="uid=1000(app) gid=1000(app)")

        evidence = await exploiter._gather_evidence("; id", response)

        self.assertEqual(evidence["mode"], "Access Mode")
        handoff = evidence["data"]["operator_handoff"]
        action_ids = {action["id"] for action in handoff["available_actions"]}
        self.assertIn("replay_proof_request", action_ids)
        self.assertIn("run_readonly_command", action_ids)
        self.assertEqual(handoff["command_channel"]["allowed_commands"][0], "id")

    async def test_command_injection_success_accepts_non_root_command_output(self):
        exploiter = self._make_exploiter(
            vuln_type="command injection",
            base_payload="; id",
            vector="Query: cmd",
            post_action="Access Mode",
        )
        response = httpx.Response(200, text="uid=1000(app) gid=1000(app) groups=1000(app)")

        self.assertTrue(await exploiter._check_success("; id", response))

    async def test_success_result_contains_operator_handoff(self):
        exploiter = self._make_exploiter(vuln_type="ssti", base_payload="{{7*7}}", vector="Query: q")

        async def skip_fingerprint():
            return None

        async def fake_send_payload(_payload):
            return httpx.Response(200, text="Template output: 49")

        async def no_ai_guide():
            return {"title": "Operator handoff", "steps": []}

        exploiter.fingerprint_target = skip_fingerprint
        exploiter._send_payload = fake_send_payload
        exploiter._generate_exploit_guide = no_ai_guide

        result = await exploiter.run()

        self.assertTrue(result["success"])
        self.assertIn("operator_handoff", result)
        self.assertEqual(result["operator_handoff"]["state"], "operator_handoff")
        self.assertEqual(result["operator_handoff"]["stop_reason"], "access_proof_reached")
        self.assertIn("single_request_replay", result["reproduction_script"].lower())

    def test_readonly_command_payload_replaces_only_allowed_commands(self):
        self.assertEqual(build_readonly_command_payload("; id", "whoami"), "; whoami")
        self.assertIsNone(build_readonly_command_payload("; id", "rm -rf /"))

    async def test_operator_action_endpoint_requires_confirmation(self):
        import main

        previous = main._exploit_result
        main._exploit_result = {
            "operator_handoff": {
                "available_actions": [
                    {"id": "replay_proof_request", "requires_confirmation": True},
                    {"id": "inspect_access_evidence", "requires_confirmation": False},
                ],
                "replay": {"method": "GET", "url": "https://example.test/proof"},
            },
            "evidence": {"summary": "proof"},
        }
        try:
            blocked = await main.run_exploit_operator_action(
                main.ExploitActionRequest(action="replay_proof_request")
            )
            inspected = await main.run_exploit_operator_action(
                main.ExploitActionRequest(action="inspect_access_evidence")
            )
        finally:
            main._exploit_result = previous

        self.assertIn("Confirmation is required", blocked["error"])
        self.assertEqual(inspected["action"], "inspect_access_evidence")


if __name__ == "__main__":
    unittest.main()
