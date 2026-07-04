import pytest


class FakeResponse:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json_body = json_body or {}

    def json(self):
        return self._json_body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_private_oast_settings_from_environment(monkeypatch, tmp_path):
    from core import oast_listener

    monkeypatch.setenv("SENTINEL_OAST_SETTINGS_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setenv("PRIVATE_OAST_DOMAIN", "oast.private.test")
    monkeypatch.setenv("PRIVATE_OAST_TOKEN", "secret-token")
    oast_listener.reload_oast_settings()

    settings = oast_listener.get_oast_settings()

    assert settings["domain"] == "oast.private.test"
    assert settings["token_configured"] is True
    assert settings["private"] is True
    assert settings["poll_url"] == "https://oast.private.test/poll"
    assert settings["register_url"] == "https://oast.private.test/register"


@pytest.mark.asyncio
async def test_oob_tracker_uses_private_oast_token_for_polling(monkeypatch, tmp_path):
    from core import oast_listener, oob_tracker

    monkeypatch.setenv("SENTINEL_OAST_SETTINGS_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setenv("PRIVATE_OAST_DOMAIN", "oast.private.test")
    monkeypatch.setenv("PRIVATE_OAST_TOKEN", "secret-token")
    monkeypatch.delenv("OOB_POLL_URL", raising=False)
    oast_listener.reload_oast_settings()
    seen = {}

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            seen["url"] = url
            seen["headers"] = headers or {}
            return FakeResponse(json_body={"interactions": []})

    monkeypatch.setattr(oob_tracker.httpx, "AsyncClient", FakeClient)

    stats = await oob_tracker.poll_remote_oob_server()

    assert stats == {"interactions": 0, "matched": 0, "created": 0}
    assert seen["url"] == "https://oast.private.test/poll"
    assert seen["headers"]["Authorization"] == "Bearer secret-token"


def test_public_oast_fallback_logs_warning(monkeypatch, caplog, tmp_path):
    from core import oast_listener

    monkeypatch.setenv("SENTINEL_OAST_SETTINGS_PATH", str(tmp_path / "missing.json"))
    monkeypatch.delenv("PRIVATE_OAST_DOMAIN", raising=False)
    monkeypatch.delenv("PRIVATE_OAST_TOKEN", raising=False)
    monkeypatch.delenv("OOB_BASE_DOMAIN", raising=False)
    oast_listener.reload_oast_settings()

    with caplog.at_level("WARNING"):
        settings = oast_listener.get_oast_settings()

    assert settings["private"] is False
    assert settings["domain"] == "oob.invalid"
    assert any("public OAST" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_oast_settings_api_updates_runtime_and_masks_token(client, monkeypatch, tmp_path):
    import main

    from core import oast_listener

    monkeypatch.setenv("SENTINEL_OAST_SETTINGS_PATH", str(tmp_path / "oast.json"))
    oast_listener.reload_oast_settings()
    calls = []

    async def fake_reconfigure():
        calls.append("reconfigured")

    monkeypatch.setattr(main, "reconfigure_oob_poller", fake_reconfigure)

    response = await client.post(
        "/api/settings/oast",
        json={"domain": "oast.internal.test", "token": "new-token", "provider": "private-interactsh"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == "oast.internal.test"
    assert body["token_configured"] is True
    assert "token" not in body
    assert calls == ["reconfigured"]

    get_response = await client.get("/api/settings/oast")

    assert get_response.status_code == 200
    assert get_response.json()["domain"] == "oast.internal.test"
