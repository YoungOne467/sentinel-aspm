import pytest
from unittest.mock import AsyncMock, patch
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import Target, CrawledURL, ShadowAPI, gen_id
from core.cve_mapper import map_cves_for_tech_stack
from core.dlp_parser import ROUTE_REGEX, is_api_route
from core.ai_triage import ai_triage

def test_cve_mapping():
    # Test mapping with Tomcat 9.0 (should match CVE-2020-1938 and CVE-2022-22965)
    tomcat_cves = map_cves_for_tech_stack(["Tomcat 9.0"])
    assert len(tomcat_cves) == 2
    cve_ids = {cve["cve_id"] for cve in tomcat_cves}
    assert "CVE-2020-1938" in cve_ids
    assert "CVE-2022-22965" in cve_ids

    # Test mapping with nginx 1.23 (should match CVE-2022-41741)
    nginx_cves = map_cves_for_tech_stack(["nginx 1.23"])
    assert len(nginx_cves) == 1
    assert nginx_cves[0]["cve_id"] == "CVE-2022-41741"

    # Test mapping with invalid / unmatched tech stack
    unmatched_cves = map_cves_for_tech_stack(["UnknownTech 1.0"])
    assert len(unmatched_cves) == 0

def test_js_route_extraction():
    # Test valid API route extraction using ROUTE_REGEX
    js_content = 'const api = "/api/v1/users"; const legacy = "/api/items/details";'
    matches = ROUTE_REGEX.findall(js_content)
    assert "/api/v1/users" in matches
    assert "/api/items/details" in matches

    # Test validation function (is_api_route)
    assert is_api_route("/api/v1/users") is True
    assert is_api_route("/api/items") is True
    # Exclude common static assets
    assert is_api_route("/api/v1/logo.png") is False
    assert is_api_route("/static/css/main.css") is False
    assert is_api_route("/api/config.json") is False

@pytest.mark.asyncio
async def test_api_endpoints_and_triage(client):
    # 1. Create a target in the db
    async with AsyncSessionLocal() as session:
        target = Target(
            id=gen_id(),
            name="CVE & Routes Test Target",
            host="cve-routes.local",
            port=80,
            tech_stack=["Tomcat 9.0"],
            known_cves=map_cves_for_tech_stack(["Tomcat 9.0"])
        )
        session.add(target)
        await session.commit()
        target_id = target.id

        # Create a crawled URL
        crawled_url = CrawledURL(
            id=gen_id(),
            target_id=target_id,
            host="cve-routes.local",
            url="http://cve-routes.local/main.js",
            is_new=True
        )
        session.add(crawled_url)
        await session.commit()
        crawled_url_id = crawled_url.id

        # Insert some shadow API routes
        route_1 = ShadowAPI(
            crawled_url_id=crawled_url_id,
            route="/api/v1/users"
        )
        route_2 = ShadowAPI(
            crawled_url_id=crawled_url_id,
            route="/api/v1/admin/debug"
        )
        session.add(route_1)
        session.add(route_2)
        await session.commit()

    # 2. Test GET /api/targets/{target_id}/routes
    response = await client.get(f"/api/targets/{target_id}/routes")
    assert response.status_code == 200
    routes_data = response.json()
    assert len(routes_data) == 2
    extracted_routes = {item["route"] for item in routes_data}
    assert "/api/v1/users" in extracted_routes
    assert "/api/v1/admin/debug" in extracted_routes

    # 3. Test GET /api/topology returns shadow_apis and known_cves
    response = await client.get(f"/api/topology?target_id={target_id}")
    assert response.status_code == 200
    topology_data = response.json()
    assert "nodes" in topology_data
    assert "edges" in topology_data

    # Check root node and endpoint node properties
    root_node = next((n for n in topology_data["nodes"] if n["type"] == "root"), None)
    assert root_node is not None
    assert "known_cves" in root_node
    # Should have tomcat CVEs mapped
    assert len(root_node["known_cves"]) == 2

    endpoint_node = next((n for n in topology_data["nodes"] if n["type"] == "endpoint"), None)
    assert endpoint_node is not None
    assert "shadow_apis" in endpoint_node
    assert "/api/v1/users" in endpoint_node["shadow_apis"]

    from unittest.mock import MagicMock
    mock_ollama_response = MagicMock()
    mock_ollama_response.status_code = 200
    mock_ollama_response.json.return_value = {
        "response": "<|think|>\nChecking Tomcat version 9.0 and related vulnerabilities. We have CVE-2020-1938.\n</|think|>\nHost cve-routes.local is running Apache Tomcat 9.0, exposing CVE-2020-1938 (Ghostcat). Severe vulnerability, needs patch immediately."
    }

    # Since post is an async method, the patch return_value needs to be a coroutine.
    # We can use AsyncMock for post and set its return_value to mock_ollama_response.
    mock_post_method = AsyncMock(return_value=mock_ollama_response)

    with patch("httpx.AsyncClient.post", mock_post_method) as mock_post:
        response = await client.get(f"/api/targets/{target_id}/triage")
        assert response.status_code == 200
        triage_data = response.json()
        assert "summary" in triage_data
        summary = triage_data["summary"]
        
        # Verify that thinking tags and the content inside them are successfully stripped
        assert "<|think|>" not in summary
        assert "</|think|>" not in summary
        assert "Checking Tomcat version 9.0" not in summary
        assert "exposing CVE-2020-1938" in summary

        # Check that the request was made to Ollama's endpoint
        mock_post.assert_called_once()
        called_url = mock_post.call_args[0][0]
        assert "11434" in called_url

    # 5. Clean up db records
    async with AsyncSessionLocal() as session:
        # Delete routes
        db_routes_res = await session.execute(select(ShadowAPI).where(ShadowAPI.crawled_url_id == crawled_url_id))
        db_routes = db_routes_res.scalars().all()
        for r in db_routes:
            await session.delete(r)

        # Delete crawled url
        db_url = await session.get(CrawledURL, crawled_url_id)
        if db_url:
            await session.delete(db_url)

        # Delete target
        db_target = await session.get(Target, target_id)
        if db_target:
            await session.delete(db_target)

        await session.commit()
