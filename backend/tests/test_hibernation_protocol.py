import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (ROOT, BACKEND):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


def test_bootloader_uses_project_signal_file():
    import sentinel_bootloader

    config = sentinel_bootloader.BootloaderConfig(project_root=ROOT)

    assert config.signal_file == ROOT / "scratch" / "hibernate.sig"
    assert config.backend_cwd == ROOT / "backend"
    assert config.frontend_cwd == ROOT / "aspm-frontend"


def test_offline_processor_drains_pending_targets_and_vulnerabilities(tmp_path):
    from offline_ai_processor import OfflineAIConfig, OfflineAIProcessor

    db_path = tmp_path / "telemetry.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE targets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER,
            tags TEXT,
            notes TEXT,
            tech_stack TEXT,
            risk_score REAL,
            known_cves TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE vulnerabilities (
            id TEXT PRIMARY KEY,
            crawled_url_id TEXT,
            target_id TEXT,
            vuln_type TEXT NOT NULL,
            severity TEXT,
            title TEXT NOT NULL,
            description TEXT,
            evidence TEXT,
            sink TEXT,
            payload TEXT,
            source TEXT,
            raw_data TEXT,
            status TEXT,
            created_at TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO targets (id, name, host, notes) VALUES (?, ?, ?, ?)",
        ("target-1", "Example", "example.local", ""),
    )
    conn.execute(
        """
        INSERT INTO vulnerabilities
            (id, target_id, vuln_type, severity, title, description, evidence, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "vuln-1",
            "target-1",
            "IDOR",
            "high",
            "Object ownership bypass",
            "Direct object reference",
            "GET /users/2 returned 200",
            None,
        ),
    )
    conn.commit()
    conn.close()

    class FakeOllama:
        def __init__(self):
            self.prompts = []
            self.responses = [
                "Target risk summary",
                "AI validation summary\n```yaml\nid: generated-idor\ninfo:\n  name: generated\n```",
            ]

        def generate(self, prompt: str) -> str:
            self.prompts.append(prompt)
            return self.responses.pop(0)

    fake = FakeOllama()
    processor = OfflineAIProcessor(OfflineAIConfig(db_path=db_path), ollama=fake)

    stats = processor.run()

    assert stats == {"targets": 1, "vulnerabilities": 1, "errors": 0}
    assert len(fake.prompts) == 2

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    target = conn.execute("SELECT * FROM targets WHERE id = 'target-1'").fetchone()
    vulnerability = conn.execute("SELECT * FROM vulnerabilities WHERE id = 'vuln-1'").fetchone()
    conn.close()

    assert target["ai_triage_pending"] == 0
    assert target["ai_summary"] == "Target risk summary"
    assert vulnerability["ai_triage_pending"] == 0
    assert vulnerability["ai_summary"].startswith("AI validation summary")
    assert "generated-idor" in vulnerability["ai_template"]
    raw_data = json.loads(vulnerability["raw_data"])
    assert raw_data["ai_batch"]["model"] == processor.config.model


@pytest.mark.asyncio
async def test_hibernate_endpoint_writes_signal_file(client, monkeypatch, tmp_path):
    import main

    signal_file = tmp_path / "hibernate.sig"
    monkeypatch.setattr(main, "HIBERNATE_SIGNAL_FILE", signal_file)

    response = await client.post("/api/system/hibernate")

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "hibernate_requested"
    assert signal_file.exists()
    signal = json.loads(signal_file.read_text(encoding="utf-8"))
    assert signal["action"] == "hibernate"
