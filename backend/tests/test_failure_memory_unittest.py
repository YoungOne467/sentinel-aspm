import json
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

import httpx

from agents.exploit_tester import AutonomousExploiter
from core.failure_memory import FailureMemoryStore, classify_defense_signals


async def _noop_broadcast(_message):
    return None


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@contextmanager
def _temp_memory_dir():
    scratch = Path.cwd() / "scratch" / "test_failure_memory"
    scratch.mkdir(parents=True, exist_ok=True)
    path = scratch / f"case_{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    yield str(path)


class FailureMemoryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        exploiter = getattr(self, "exploiter", None)
        if exploiter is not None:
            await exploiter.client.aclose()
            await exploiter.oast_client.close()

    def test_defense_signal_classification_detects_waf_rate_limit_and_noise(self):
        response = httpx.Response(
            403,
            headers={"Server": "cloudflare", "CF-Ray": "abc", "Retry-After": "30"},
            text="request blocked by WAF challenge",
        )

        signals = classify_defense_signals(403, response=response)

        self.assertIn("waf_or_access_block", signals)
        self.assertIn("cloudflare", signals)
        self.assertIn("rate_limit_hint", signals)
        self.assertIn("challenge_or_bot_defense", signals)

    def test_failure_memory_writes_general_and_site_specific_records(self):
        with _temp_memory_dir() as temp_dir:
            store = FailureMemoryStore(base_dir=temp_dir)
            response = httpx.Response(
                403,
                headers={"Server": "cloudflare", "CF-Ray": "abc"},
                text="request blocked by waf",
            )

            paths = store.record_failure(
                campaign_id="camp-1",
                target_url="https://app.example.test/api/search?q=1",
                vuln_type="sql injection",
                vector="Query: q",
                payload="' OR '1'='1",
                status_code=403,
                response=response,
                attempt_no=1,
                ai_feedback="WAF signature block; try context shift.",
                generated_mutations=["%27%20OR%201%3D1"],
                request_metadata={"method": "GET", "url": "https://app.example.test/api/search?q=%27"},
            )

            general_records = _read_jsonl(Path(paths["general_path"]))
            site_records = _read_jsonl(Path(paths["site_path"]))

            self.assertEqual(general_records[0]["record_type"], "general_failure")
            self.assertNotIn("target_url", general_records[0])
            self.assertEqual(general_records[0]["vuln_type"], "sql injection")
            self.assertIn("cloudflare", general_records[0]["defense_signals"])
            self.assertIn("target_url", site_records[0])
            self.assertEqual(site_records[0]["record_type"], "site_failure")
            self.assertEqual(site_records[0]["campaign_id"], "camp-1")
            self.assertEqual(site_records[0]["request"]["method"], "GET")

    def test_site_campaign_summary_tracks_failures_until_success(self):
        with _temp_memory_dir() as temp_dir:
            store = FailureMemoryStore(base_dir=temp_dir)
            target = "https://shop.example.test/search"

            store.record_failure(
                campaign_id="camp-2",
                target_url=target,
                vuln_type="ssti",
                vector="Query: q",
                payload="{{7*7}}",
                status_code=200,
                response=httpx.Response(200, text="There are 49 products"),
                attempt_no=1,
                ai_feedback="Reflected but not evaluated.",
            )
            store.record_failure(
                campaign_id="camp-2",
                target_url=target,
                vuln_type="ssti",
                vector="Query: q",
                payload="${7*7}",
                status_code=500,
                response=httpx.Response(500, text="template parse error"),
                attempt_no=2,
                ai_feedback="Syntax mismatch.",
            )
            store.record_success(
                campaign_id="camp-2",
                target_url=target,
                vuln_type="ssti",
                vector="Query: q",
                payload="<%= 7*7 %>",
                status_code=200,
                attempts=3,
                response=httpx.Response(200, text="49"),
                evidence={"summary": "access proof captured"},
            )

            summary = store.summarize_site_memory(target, campaign_id="camp-2")

            self.assertEqual(summary["campaign_id"], "camp-2")
            self.assertEqual(summary["failure_count"], 2)
            self.assertTrue(summary["succeeded"])
            self.assertEqual(summary["success_payload"], "<%= 7*7 %>")
            self.assertIn("server_error_or_exception", summary["defense_signals"])
            self.assertEqual(len(summary["failed_payloads"]), 2)

    async def test_exploiter_records_failure_memory_without_breaking_scan(self):
        with _temp_memory_dir() as temp_dir:
            self.exploiter = AutonomousExploiter(
                target_url="https://app.example.test/search",
                vuln_type="sql injection",
                base_payload="' OR '1'='1",
                vector="Query: q",
                broadcast_cb=_noop_broadcast,
                post_action="Aggressive Proof of Access",
                use_ai=False,
            )
            self.exploiter.failure_memory = FailureMemoryStore(base_dir=temp_dir)
            self.exploiter.last_request_metadata = {"method": "GET", "url": "https://app.example.test/search?q=x"}
            response = httpx.Response(406, headers={"Server": "mod_security"}, text="not acceptable")

            paths = await self.exploiter._record_failure_memory(
                payload="' OR '1'='1",
                status_code=406,
                response=response,
                response_text=response.text,
                attempt_no=1,
                generated_mutations=["%27%20OR%201%3D1"],
            )

            self.assertTrue(Path(paths["general_path"]).exists())
            site_records = _read_jsonl(Path(paths["site_path"]))
            self.assertEqual(site_records[0]["payload"], "' OR '1'='1")
            self.assertIn("waf_or_access_block", site_records[0]["defense_signals"])


if __name__ == "__main__":
    unittest.main()
