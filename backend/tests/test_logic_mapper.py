import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import Target, CrawledURL, gen_id
from core.logic_mapper import aggregate_session_traffic
from core.ai_triage import ai_triage

@pytest.mark.asyncio
async def test_logic_mapper_flow(client):
    # 1. Create target
    async with AsyncSessionLocal() as session:
        target = Target(
            id=gen_id(),
            name="Logic Mapper Test Target",
            host="logic-mapper.local",
            port=80,
            tech_stack=["React"],
            known_cves=[]
        )
        session.add(target)
        await session.commit()
        target_id = target.id

        # 2. Create chronological crawled URLs with different methods and status codes
        crawled1 = CrawledURL(
            id=gen_id(),
            target_id=target_id,
            host="logic-mapper.local",
            url="http://logic-mapper.local/login",
            method="GET",
            status_code=200,
            is_new=True,
            created_at=datetime.now(timezone.utc)
        )
        crawled2 = CrawledURL(
            id=gen_id(),
            target_id=target_id,
            host="logic-mapper.local",
            url="http://logic-mapper.local/api/checkout",
            method="POST",
            status_code=201,
            is_new=True,
            created_at=datetime.now(timezone.utc)
        )
        session.add(crawled1)
        session.add(crawled2)
        await session.commit()
        crawled1_id = crawled1.id
        crawled2_id = crawled2.id

    # 3. Test aggregate_session_traffic directly
    traffic = await aggregate_session_traffic(target_id)
    assert len(traffic) == 2
    assert traffic[0]["method"] == "GET"
    assert traffic[0]["url"] == "http://logic-mapper.local/login"
    assert traffic[0]["status_code"] == 200
    assert traffic[1]["method"] == "POST"
    assert traffic[1]["url"] == "http://logic-mapper.local/api/checkout"
    assert traffic[1]["status_code"] == 201

    # 4. Mock the LLM endpoint response for AI state machine generation
    mock_ollama_response = MagicMock()
    mock_ollama_response.status_code = 200
    mock_ollama_response.json.return_value = {
        "choices": [{
            "message": {
                "content": "<|think|>\nAnalyzing flow...\n</|think|>\ngraph TD;\n    A[GET /login] -->|200| B(POST /api/checkout);\n"
            }
        }]
    }
    
    mock_post_method = AsyncMock(return_value=mock_ollama_response)

    # 5. Make request to GET /api/targets/{target_id}/logic-map
    with patch.object(ai_triage, "check_availability", AsyncMock(return_value=True)), \
         patch("httpx.AsyncClient.post", mock_post_method) as mock_post:
         
        response = await client.get(f"/api/targets/{target_id}/logic-map")
        assert response.status_code == 200
        data = response.json()
        assert "logic_map" in data
        graph = data["logic_map"]
        assert "graph TD" in graph
        assert "A[GET /login]" in graph
        assert "<|think|>" not in graph
        assert "</|think|>" not in graph
        assert "Analyzing flow" not in graph
        
        # Verify that calling it again uses the cached map and does not call LLM post
        mock_post.reset_mock()
        response2 = await client.get(f"/api/targets/{target_id}/logic-map")
        assert response2.status_code == 200
        data2 = response2.json()
        assert data2["logic_map"] == graph
        mock_post.assert_not_called()

    # 6. Clean up db records
    async with AsyncSessionLocal() as session:
        c1 = await session.get(CrawledURL, crawled1_id)
        if c1:
            await session.delete(c1)
        c2 = await session.get(CrawledURL, crawled2_id)
        if c2:
            await session.delete(c2)
        t = await session.get(Target, target_id)
        if t:
            await session.delete(t)
        await session.commit()
