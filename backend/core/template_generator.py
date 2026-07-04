import asyncio
import json
import logging
import os
import re
import subprocess
import textwrap
import uuid
from pathlib import Path
from typing import Any

import httpx
import yaml
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import CrawledURL, Vulnerability


logger = logging.getLogger("sentinel.template_generator")

OLLAMA_URL = os.getenv("OLLAMA_GENERATE_URL", "http://localhost:11434/api/generate")
# HARDCODED: Enterprise Directive — no dynamic resolution
OLLAMA_MODEL = "hf.co/Melvin56/Phi-4-mini-instruct-abliterated-GGUF:Q4_K_M"


def extract_yaml_block(response_text: str) -> str:
    fenced = re.search(r"```(?:yaml|yml)?\s*([\s\S]*?)```", response_text, re.IGNORECASE)
    yaml_text = textwrap.dedent(fenced.group(1) if fenced else response_text).strip()
    indents = [
        len(line) - len(line.lstrip())
        for line in yaml_text.splitlines()
        if line.strip()
    ]
    if indents and min(indents) > 0:
        trim = min(indents)
        yaml_text = "\n".join(line[trim:] if len(line) >= trim else line for line in yaml_text.splitlines())
    else:
        lines = yaml_text.splitlines()
        tail_indents = [
            len(line) - len(line.lstrip())
            for line in lines[1:]
            if line.strip()
        ]
        if tail_indents and min(tail_indents) > 0:
            trim = min(tail_indents)
            yaml_text = "\n".join(
                [lines[0]] + [line[trim:] if len(line) >= trim else line for line in lines[1:]]
            )
    parsed = yaml.safe_load(yaml_text)
    if not isinstance(parsed, dict) or "id" not in parsed or "info" not in parsed:
        raise ValueError("Ollama response did not contain a valid Nuclei YAML template")
    return yaml.safe_dump(parsed, sort_keys=False)


def parse_nuclei_json_output(output: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            findings.append(parsed)
    return findings


def _scratch_dir() -> Path:
    root = Path(__file__).resolve().parents[2]
    candidates = [root / "scratch", Path(__file__).resolve().parents[1] / "scratch"]
    for scratch in candidates:
        try:
            scratch.mkdir(parents=True, exist_ok=True)
            probe = scratch / ".write_probe"
            probe.write_text("", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return scratch
        except OSError:
            continue
    raise OSError("No writable scratch directory found for generated Nuclei templates")


def _run_nuclei(template_path: Path, endpoint: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["nuclei.exe", "-json", "-t", str(template_path), "-u", endpoint],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


async def _persist_nuclei_findings(endpoint: str, findings: list[dict[str, Any]]) -> None:
    if not findings:
        return

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(CrawledURL).where(CrawledURL.url == endpoint))
        crawled_url = result.scalars().first()
        for finding in findings:
            template_id = finding.get("template-id") or finding.get("templateID") or "custom-idor-bola"
            severity = finding.get("info", {}).get("severity") if isinstance(finding.get("info"), dict) else None
            session.add(
                Vulnerability(
                    crawled_url_id=crawled_url.id if crawled_url else None,
                    target_id=crawled_url.target_id if crawled_url else None,
                    vuln_type="IDOR/BOLA",
                    severity=str(severity or "medium"),
                    title=f"Custom Nuclei finding: {template_id}",
                    description="AI-generated Nuclei template reported a potential IDOR/BOLA issue.",
                    evidence=json.dumps(finding, ensure_ascii=False),
                    source="template_generator",
                    raw_data=finding,
                )
            )
        await session.commit()


async def generate_and_run_custom_template(endpoint: str, method: str) -> dict[str, Any]:

    resolved_model = OLLAMA_MODEL

    prompt = f"""
You are generating a single Nuclei YAML template for authorized security testing.
Output only YAML. No prose.
The template must be highly specific to this endpoint and test for IDOR or BOLA:
endpoint: {endpoint}
method: {method.upper()}

Requirements:
- Include id, info.name, info.author, info.severity, info.description, and requests/http.
- Use safe, non-destructive requests.
- Prefer matcher logic that detects authorization boundary weakness, object ownership leaks, or unexpected 2xx access.
- Do not include placeholders except nuclei variables.
"""

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            OLLAMA_URL,
            json={
                "model": resolved_model,
                "prompt": prompt,
                "stream": False,
                "keep_alive": 0,
                "options": {
                    "num_ctx": 16384
                }
            },
        )
        response.raise_for_status()
        body = response.json()

    yaml_text = extract_yaml_block(str(body.get("response", "")))
    template_path = _scratch_dir() / f"custom-idor-bola-{uuid.uuid4().hex}.yaml"
    template_path.write_text(yaml_text, encoding="utf-8")

    completed = await asyncio.to_thread(_run_nuclei, template_path, endpoint)
    findings = parse_nuclei_json_output(completed.stdout)
    await _persist_nuclei_findings(endpoint, findings)

    if completed.returncode not in (0, 1):
        logger.warning("Nuclei exited with %s: %s", completed.returncode, completed.stderr)

    return {
        "template_path": str(template_path),
        "returncode": completed.returncode,
        "stderr": completed.stderr,
        "findings": findings,
    }
