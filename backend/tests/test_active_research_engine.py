import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, DiscoveredParameter, Target, Vulnerability, gen_id


def test_extract_js_parameters_finds_query_keys_and_flags():
    from core.dlp_parser import extract_js_parameters

    js = """
      const url = "/api/users?user_id=" + id + "&debug=true";
      const admin_role = "admin_role";
      fetch(`/api/audit?tenantId=${tenantId}&include_deleted=false`);
    """

    params = extract_js_parameters(js)

    names = {p["name"] for p in params}
    assert {"user_id", "debug", "tenantId", "include_deleted", "admin_role"}.issubset(names)
    assert any(p["source"] == "query_string" and p["name"] == "user_id" for p in params)
    assert any(p["source"] == "identifier" and p["name"] == "admin_role" for p in params)


@pytest.mark.asyncio
async def test_discovered_parameter_links_to_crawled_url():
    target_id = gen_id()
    crawled_url_id = gen_id()

    async with AsyncSessionLocal() as session:
        target = Target(id=target_id, name="Param Target", host="params.local")
        crawled_url = CrawledURL(
            id=crawled_url_id,
            target_id=target_id,
            host="params.local",
            url="http://params.local/app.js",
        )
        session.add_all([target, crawled_url])
        await session.commit()

        session.add(
            DiscoveredParameter(
                crawled_url_id=crawled_url_id,
                name="user_id",
                source="query_string",
                context='"/api/users?user_id="',
                confidence=0.95,
            )
        )
        await session.commit()

        result = await session.execute(
            select(DiscoveredParameter).where(
                DiscoveredParameter.crawled_url_id == crawled_url_id
            )
        )
        stored = result.scalar_one()
        assert stored.crawled_url_id == crawled_url_id
        assert stored.name == "user_id"

        await session.delete(crawled_url)
        await session.delete(target)
        await session.commit()


def test_dom_tracker_builds_sink_finding_from_console_event():
    from core.dom_tracker import build_dom_xss_finding

    finding = build_dom_xss_finding(
        url="http://app.local/#sentinel_taint_123",
        sink="eval",
        evidence="DOM_XSS_CANARY:sink=eval;value=sentinel_taint_123",
        canary="sentinel_taint_123",
    )

    assert finding["type"] == "DOM-XSS"
    assert finding["severity"] == "high"
    assert finding["sink"] == "eval"
    assert finding["payload"] == "sentinel_taint_123"


@pytest.mark.asyncio
async def test_vulnerability_model_can_store_dom_finding():
    target_id = gen_id()
    crawled_url_id = gen_id()

    async with AsyncSessionLocal() as session:
        target = Target(id=target_id, name="Vuln Target", host="vuln.local")
        crawled_url = CrawledURL(
            id=crawled_url_id,
            target_id=target_id,
            host="vuln.local",
            url="http://vuln.local/",
        )
        vulnerability = Vulnerability(
            crawled_url_id=crawled_url_id,
            target_id=target_id,
            vuln_type="DOM-XSS",
            severity="high",
            title="DOM XSS canary reached eval",
            evidence="sentinel_taint_123",
            sink="eval",
            payload="sentinel_taint_123",
        )
        session.add_all([target, crawled_url, vulnerability])
        await session.commit()

        result = await session.execute(
            select(Vulnerability).where(Vulnerability.crawled_url_id == crawled_url_id)
        )
        stored = result.scalar_one()
        assert stored.vuln_type == "DOM-XSS"
        assert stored.sink == "eval"

        await session.delete(crawled_url)
        await session.delete(target)
        await session.commit()


def test_template_generator_extracts_yaml_block_and_parses_jsonl():
    from core.template_generator import extract_yaml_block, parse_nuclei_json_output

    response = """
    Here is the template:
    ```yaml
    id: custom-idor-test
    info:
      name: Custom IDOR Test
      severity: medium
    requests: []
    ```
    """
    yaml_block = extract_yaml_block(response)
    assert yaml_block.startswith("id: custom-idor-test")

    output = "\n".join(
        [
            json.dumps({"template-id": "custom-idor-test", "matched-at": "http://api.local/users/1"}),
            "not-json",
        ]
    )
    findings = parse_nuclei_json_output(output)
    assert findings == [
        {"template-id": "custom-idor-test", "matched-at": "http://api.local/users/1"}
    ]


@pytest.mark.asyncio
async def test_template_generator_calls_ollama_and_nuclei_with_to_thread():
    from core.template_generator import generate_and_run_custom_template

    ollama_response = MagicMock()
    ollama_response.json.return_value = {
        "response": "```yaml\nid: custom-bola\ninfo:\n  name: BOLA\n  severity: high\nrequests: []\n```"
    }
    ollama_response.raise_for_status.return_value = None

    completed = MagicMock()
    completed.stdout = json.dumps({"template-id": "custom-bola", "matched-at": "http://api.local/users/1"})
    completed.stderr = ""
    completed.returncode = 0

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=ollama_response)), patch(
        "asyncio.to_thread", new=AsyncMock(return_value=completed)
    ):
        result = await generate_and_run_custom_template("http://api.local/users/1", "GET")

    assert result["template_path"].endswith(".yaml")
    assert result["findings"][0]["template-id"] == "custom-bola"
