"""
Offline AI batch processor for SENTINEL hibernation mode.

Run this script while the FastAPI backend and React frontend are stopped. It
drains records marked ai_triage_pending, sends them to local Ollama, persists
AI output, and exits.

Enterprise Directives Implemented:
- asyncio.Semaphore(15)
- HTTPClientPool
- 3-Strike Circuit Breaker
- keep_alive=0 and num_ctx=4096
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import sys
import time
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from core.http_pool import HTTPClientPool

LOGGER = logging.getLogger("sentinel.offline_ai")

OUTDATED_TECH_PATTERNS = (
    re.compile(r"\bnginx\s+1\.18\.0\b", re.IGNORECASE),
    re.compile(r"\bapache\s+tomcat\s+9\.0\.1\b", re.IGNORECASE),
    re.compile(r"\btomcat\s+9\.0\.1\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class OfflineAIConfig:
    db_path: Path = Path(__file__).resolve().with_name("telemetry.db")
    ollama_url: str = os.getenv("OLLAMA_GENERATE_URL", "http://localhost:11434/api/generate")
    model: str = "hf.co/Melvin56/Phi-4-mini-instruct-abliterated-GGUF:Q4_K_M"
    timeout_seconds: float = float(os.getenv("OLLAMA_TIMEOUT", "180"))


class CircuitBreaker:
    def __init__(self, threshold: int = 3, cooldown: float = 60.0):
        self.threshold = threshold
        self.cooldown = cooldown
        self.failures = 0
        self.opened_at = 0.0
        self.state = "CLOSED"

    def allow_request(self) -> bool:
        if self.state == "OPEN":
            if time.monotonic() - self.opened_at >= self.cooldown:
                self.state = "HALF_OPEN"
                return True
            return False
        return True

    def record_success(self):
        if self.state != "CLOSED":
            LOGGER.info("Circuit breaker CLOSED — LLM recovered.")
        self.failures = 0
        self.state = "CLOSED"

    def record_failure(self):
        self.failures += 1
        LOGGER.warning("Circuit breaker strike %d/%d", self.failures, self.threshold)
        if self.failures >= self.threshold:
            self.state = "OPEN"
            self.opened_at = time.monotonic()
            LOGGER.critical("Circuit breaker OPEN — requests blocked for %.0fs.", self.cooldown)


class OllamaGenerateClient:
    def __init__(self, config: OfflineAIConfig):
        self._config = config
        self._circuit_breaker = CircuitBreaker()

    async def generate(self, prompt: str) -> str:
        if not self._circuit_breaker.allow_request():
            raise RuntimeError("Circuit breaker is OPEN. LLM requests blocked.")

        payload = {
            "model": self._config.model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": 0,
            "options": {
                "num_ctx": 16384
            }
        }
        client = await HTTPClientPool.get_client()
        try:
            response = await client.post(self._config.ollama_url, json=payload, timeout=self._config.timeout_seconds)
            if response.status_code >= 500:
                self._circuit_breaker.record_failure()
                response.raise_for_status()
                
            self._circuit_breaker.record_success()
            response.raise_for_status()
            body = response.json()
            return str(body.get("response", "")).strip()
        except httpx.HTTPStatusError as e:
            if e.response.status_code >= 500:
                self._circuit_breaker.record_failure()
            raise
        except Exception:
            self._circuit_breaker.record_failure()
            raise


def get_db_connection(db_path: Path | str) -> sqlite3.Connection:
    """Helper to establish SQLite connection with WAL pragmas."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _fetch_pending_data(db_path: Path) -> tuple[list[sqlite3.Row], list[sqlite3.Row], list[sqlite3.Row]]:
    """Helper executed in a worker thread to query pending scan records."""
    with get_db_connection(db_path) as conn:
        conn.row_factory = sqlite3.Row
        ensure_ai_columns(conn)
        targets = pending_targets(conn)
        vulns = pending_vulnerabilities(conn)
        patches = pending_patch_analysis_targets(conn)
    return targets, vulns, patches


def _update_target_summary(db_path: Path, summary: str, target_id: str):
    """Helper executed in a worker thread to persist AI summary."""
    with get_db_connection(db_path) as c:
        c.execute(
            "UPDATE targets SET ai_summary = ?, ai_triage_pending = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (summary, target_id),
        )
        c.commit()


def _update_vuln_summary(db_path: Path, response: str, template: str, raw_data: str, vuln_id: str):
    """Helper executed in a worker thread to persist vulnerability AI findings."""
    with get_db_connection(db_path) as c:
        c.execute(
            "UPDATE vulnerabilities SET ai_summary = ?, ai_template = ?, raw_data = ?, ai_triage_pending = 0 WHERE id = ?",
            (response, template, raw_data, vuln_id),
        )
        c.commit()


def _update_patch_analysis(db_path: Path, analysis: str, target_id: str):
    """Helper executed in a worker thread to persist AI patch analysis."""
    with get_db_connection(db_path) as c:
        c.execute(
            "UPDATE targets SET patch_analysis = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (analysis, target_id),
        )
        c.commit()


class OfflineAIProcessor:
    def __init__(self, config: OfflineAIConfig | None = None, ollama: Any | None = None):
        self.config = config or OfflineAIConfig()
        self.ollama = ollama or OllamaGenerateClient(self.config)
        self.semaphore = asyncio.Semaphore(15)
        self.db_lock = asyncio.Lock()

    async def _generate(self, prompt: str) -> str:
        result = self.ollama.generate(prompt)
        if inspect.isawaitable(result):
            return await result
        return str(result)

    async def run_async(self) -> dict[str, int]:
        stats = {"targets": 0, "vulnerabilities": 0, "errors": 0}
        
        # Offload sync SQLite queries to worker thread
        targets, vulns, patches = await asyncio.to_thread(_fetch_pending_data, self.config.db_path)

        async def process_target(target):
            async with self.semaphore:
                try:
                    summary = await self._generate(build_target_prompt(target))
                    async with self.db_lock:
                        await asyncio.to_thread(_update_target_summary, self.config.db_path, summary, target["id"])
                    stats["targets"] += 1
                    LOGGER.info("AI target summary persisted for %s", target["id"])
                except Exception as exc:
                    stats["errors"] += 1
                    LOGGER.error("Target AI batch failed for %s: %s", target["id"], exc)

        async def process_vuln(vulnerability):
            async with self.semaphore:
                try:
                    response = await self._generate(build_vulnerability_prompt(vulnerability))
                    template = extract_yaml_template(response)
                    raw_data = merge_ai_batch(vulnerability["raw_data"], self.config.model, response, template)
                    async with self.db_lock:
                        await asyncio.to_thread(
                            _update_vuln_summary,
                            self.config.db_path,
                            response,
                            template,
                            raw_data,
                            vulnerability["id"]
                        )
                    stats["vulnerabilities"] += 1
                    LOGGER.info("AI vulnerability output persisted for %s", vulnerability["id"])
                except Exception as exc:
                    stats["errors"] += 1
                    LOGGER.error("Vulnerability AI batch failed for %s: %s", vulnerability["id"], exc)

        async def process_patch(target):
            async with self.semaphore:
                try:
                    outdated_tech = detect_outdated_tech(target)
                    if not outdated_tech:
                        return
                    analysis = await self._generate(build_patch_analysis_prompt(target, outdated_tech))
                    async with self.db_lock:
                        await asyncio.to_thread(_update_patch_analysis, self.config.db_path, analysis, target["id"])
                    LOGGER.info("AI patch analysis persisted for %s", target["id"])
                except Exception as exc:
                    stats["errors"] += 1
                    LOGGER.error("Patch analysis batch failed for %s: %s", target["id"], exc)

        tasks = []
        for t in targets: tasks.append(asyncio.create_task(process_target(t)))
        for v in vulns: tasks.append(asyncio.create_task(process_vuln(v)))
        for p in patches: tasks.append(asyncio.create_task(process_patch(p)))

        if tasks:
            await asyncio.gather(*tasks)

        return stats

    def run(self) -> dict[str, int]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.run_async())
        raise RuntimeError("OfflineAIProcessor.run() cannot be used inside a running event loop; await run_async().")


def ensure_ai_columns(conn: sqlite3.Connection) -> None:
    ensure_column(conn, "targets", "ai_triage_pending", "ai_triage_pending BOOLEAN NOT NULL DEFAULT 1")
    ensure_column(conn, "targets", "ai_summary", "ai_summary TEXT")
    ensure_column(conn, "targets", "patch_analysis", "patch_analysis TEXT")
    ensure_column(conn, "targets", "logic_map", "logic_map TEXT")
    ensure_column(
        conn,
        "vulnerabilities",
        "ai_triage_pending",
        "ai_triage_pending BOOLEAN NOT NULL DEFAULT 1",
    )
    ensure_column(conn, "vulnerabilities", "ai_summary", "ai_summary TEXT")
    ensure_column(conn, "vulnerabilities", "ai_template", "ai_template TEXT")
    conn.commit()


def ensure_column(conn: sqlite3.Connection, table_name: str, column_name: str, ddl: str) -> None:
    if not table_exists(conn, table_name):
        return
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})")}
    if column_name not in columns:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {ddl}")


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def pending_targets(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT id, name, host, port, tags, notes, tech_stack, risk_score, known_cves
            FROM targets
            WHERE COALESCE(ai_triage_pending, 1) = 1
            ORDER BY created_at ASC
            """
        )
    )


def pending_vulnerabilities(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    required = {
        "id", "target_id", "vuln_type", "severity", "title", "description", "evidence",
        "sink", "payload", "source", "raw_data", "status", "ai_triage_pending", "created_at",
    }
    if not required.issubset(table_columns(conn, "vulnerabilities")):
        return []
    return list(
        conn.execute(
            """
            SELECT id, target_id, vuln_type, severity, title, description, evidence,
                   sink, payload, source, raw_data, status
            FROM vulnerabilities
            WHERE COALESCE(ai_triage_pending, 1) = 1
            ORDER BY created_at ASC
            """
        )
    )


def pending_patch_analysis_targets(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    required = {"id", "name", "host", "tech_stack", "known_cves", "patch_analysis"}
    if not required.issubset(table_columns(conn, "targets")):
        return []
    return list(
        conn.execute(
            """
            SELECT id, name, host, tech_stack, known_cves, patch_analysis
            FROM targets
            WHERE (patch_analysis IS NULL OR TRIM(patch_analysis) = '')
            ORDER BY created_at ASC
            """
        )
    )


def table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    if not table_exists(conn, table_name):
        return set()
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})")}


def build_target_prompt(target: sqlite3.Row) -> str:
    return f"""You are a senior application security analyst.
Summarize this scanned target for an executive risk review.
Be concise, factual, and avoid invented findings.

Target:
- Name: {target['name']}
- Host: {target['host']}
- Port: {target['port']}
- Risk score: {target['risk_score']}
- Tech stack: {target['tech_stack']}
- Known CVEs: {target['known_cves']}
- Notes: {target['notes']}

Return only the summary."""


def build_vulnerability_prompt(vulnerability: sqlite3.Row) -> str:
    return f"""You are a senior security researcher generating offline triage output.
Analyze the vulnerability and generate:
1. A concise true-positive/impact summary.
2. A safe, non-destructive Nuclei YAML template when possible.

Vulnerability:
- Type: {vulnerability['vuln_type']}
- Severity: {vulnerability['severity']}
- Title: {vulnerability['title']}
- Description: {vulnerability['description']}
- Evidence: {vulnerability['evidence']}
- Sink: {vulnerability['sink']}
- Payload: {vulnerability['payload']}
- Source: {vulnerability['source']}

Return the summary first. If you include a template, put it in a fenced yaml block."""


def detect_outdated_tech(target: sqlite3.Row) -> list[str]:
    values = parse_inventory_value(target["tech_stack"]) + parse_inventory_value(target["known_cves"])
    text = " ".join(str(value) for value in values)
    matches: list[str] = []
    for pattern in OUTDATED_TECH_PATTERNS:
        match = pattern.search(text)
        if match:
            matches.append(match.group(0))
    return list(dict.fromkeys(matches))


def parse_inventory_value(raw_value: Any) -> list[Any]:
    if raw_value is None:
        return []
    if isinstance(raw_value, list):
        return raw_value
    if isinstance(raw_value, str):
        try:
            parsed = json.loads(raw_value)
        except ValueError:
            return [raw_value]
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return list(parsed.values())
        return [parsed]
    return [raw_value]


def build_patch_analysis_prompt(target: sqlite3.Row, outdated_tech: list[str]) -> str:
    return f"""You are a senior vulnerability researcher supporting authorized patch validation.
Write one concise paragraph describing a version-specific, non-destructive exploitation methodology
for validating whether this outdated software exposure is practically exploitable. Do not include
weaponized code; focus on observable behaviors, affected components, and safe proof points.

Target:
- Name: {target['name']}
- Host: {target['host']}
- Outdated software: {', '.join(outdated_tech)}
- Known CVE inventory: {target['known_cves']}

Return only the paragraph."""


def extract_yaml_template(response_text: str) -> str:
    fenced = re.search(r"```(?:yaml|yml)?\s*([\s\S]*?)```", response_text, re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()
    if "id:" in response_text and "info:" in response_text:
        return response_text.strip()
    return ""


def merge_ai_batch(raw_data: Any, model: str, summary: str, template: str) -> str:
    if raw_data:
        try:
            data = json.loads(raw_data) if isinstance(raw_data, str) else dict(raw_data)
        except (TypeError, ValueError):
            data = {"original_raw_data": raw_data}
    else:
        data = {}
    data["ai_batch"] = {
        "model": model,
        "summary": summary,
        "template": template,
    }
    return json.dumps(data, ensure_ascii=False)


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S",
    )


async def async_main() -> int:
    configure_logging()
    config = OfflineAIConfig()
    if not config.db_path.exists():
        LOGGER.warning("SQLite database not found: %s", config.db_path)
        return 0
    processor = OfflineAIProcessor(config)
    stats = await processor.run_async()
    await HTTPClientPool.close()
    LOGGER.info("Offline AI batch complete: %s", stats)
    return 1 if stats["errors"] else 0


def main() -> int:
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    return asyncio.run(async_main())


if __name__ == "__main__":
    sys.exit(main())
