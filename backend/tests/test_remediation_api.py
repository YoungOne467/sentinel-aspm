import pytest
from httpx import AsyncClient
from core.database import AsyncSessionLocal
from core.models import Target, Finding

@pytest.mark.anyio
async def test_evasion_settings_api(client: AsyncClient):
    # Test GET settings
    resp = await client.get("/api/settings/evasion")
    assert resp.status_code == 200
    data = resp.json()
    assert "sqli_strategy" in data
    assert "xss_strategy" in data

    # Test POST settings
    payload = {
        "sqli_strategy": "mixed_case",
        "custom_headers": {"X-Custom-Test": "123"}
    }
    resp = await client.post("/api/settings/evasion", json=payload)
    assert resp.status_code == 200
    updated_data = resp.json()
    assert updated_data["sqli_strategy"] == "mixed_case"
    assert updated_data["custom_headers"]["X-Custom-Test"] == "123"

