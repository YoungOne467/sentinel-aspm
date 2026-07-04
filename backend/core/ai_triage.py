"""
AI Triage — Local LLM integration for intelligent vulnerability auditing.
Connects to any OpenAI-compatible API endpoint (Ollama, LM Studio, vLLM, etc.).
Evaluates findings, filters false positives, drafts PoC reports.

Hardened per Enterprise Directive:
  - Hardcoded model string (no dynamic resolution)
  - Uses AI Governance CircuitBreaker
  - keep_alive=0 to unload model after each request
  - num_ctx=4096 for minimum viable context window
"""
import asyncio
import json
import logging
import os
import time
from typing import Optional, Dict, Any

import httpx

from core.database import AsyncSessionLocal
from core.models import Finding, Target, DLPFinding, CrawledURL
from sqlalchemy import select
import re

from packages.ai_governance.breaker import circuit_breaker
from packages.ai_governance.interfaces import PolicyContext

logger = logging.getLogger(__name__)

# ─── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_LLM_ENDPOINT = os.getenv("OLLAMA_OPENAI_ENDPOINT", "http://localhost:11434/v1")
DEFAULT_OLLAMA_GENERATE_URL = os.getenv("OLLAMA_GENERATE_URL", "http://localhost:11434/api/generate")
# HARDCODED: Never dynamically resolve — this is the only approved model for this hardware.
HARDCODED_MODEL = "hf.co/Melvin56/Phi-4-mini-instruct-abliterated-GGUF:Q4_K_M"
REQUEST_TIMEOUT = 120.0  # LLM can be slow

class AITriageEngine:
    """
    Local LLM bridge for:
      1. False-positive filtering — scores findings by exploitability
      2. PoC drafting — generates Markdown proof-of-concept reports

    Hardware-hardened:
      - Uses AI Governance circuit breaker
      - Serialized via semaphore (one inference at a time)
      - Model is the hardcoded 4B GGUF string
    """

    def __init__(
        self,
        endpoint: str = DEFAULT_LLM_ENDPOINT,
    ):
        self._endpoint = endpoint.rstrip("/")
        self._model = HARDCODED_MODEL
        self._available: Optional[bool] = None
        # Serialize LLM inferences — never run two in parallel on 16 GB RAM
        self._inference_semaphore = asyncio.Semaphore(1)

    async def check_availability(self) -> bool:
        """Test if the LLM endpoint is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._endpoint}/models")
                self._available = resp.status_code == 200
        except Exception:
            self._available = False
        return self._available

    async def triage_finding(self, finding_id: str) -> Dict[str, Any]:
        """
        Send a finding to the LLM for triage.
        Returns verdict: { confidence, is_true_positive, reasoning, severity_adjustment }.
        """
        if not await self.check_availability():
            return {"error": "LLM endpoint not available", "finding_id": finding_id}

        async with AsyncSessionLocal() as session:
            finding = await session.get(Finding, finding_id)
            if not finding:
                return {"error": "Finding not found"}

            prompt = self._build_triage_prompt(finding)

            try:
                result = await self._chat_completion(prompt)
                verdict = self._parse_triage_response(result)

                # Update finding with AI verdict
                finding.ai_triaged = True
                finding.ai_verdict = json.dumps(verdict)
                if verdict.get("is_false_positive"):
                    finding.status = "false_positive"
                await session.commit()

                return {"finding_id": finding_id, "verdict": verdict}
            except Exception as e:
                logger.error("AI triage failed for %s: %s", finding_id, e)
                return {"error": str(e), "finding_id": finding_id}

    async def draft_poc(self, finding_id: str) -> Dict[str, Any]:
        """Generate a Markdown PoC report for a finding."""
        if not await self.check_availability():
            return {"error": "LLM endpoint not available"}

        async with AsyncSessionLocal() as session:
            finding = await session.get(Finding, finding_id)
            if not finding:
                return {"error": "Finding not found"}

            prompt = self._build_poc_prompt(finding)

            try:
                poc_markdown = await self._chat_completion(prompt)
                return {
                    "finding_id": finding_id,
                    "poc_report": poc_markdown,
                    "format": "markdown",
                }
            except Exception as e:
                logger.error("PoC generation failed for %s: %s", finding_id, e)
                return {"error": str(e)}

    async def batch_triage(self, finding_ids: list[str]) -> list[Dict[str, Any]]:
        """Triage multiple findings sequentially (to avoid overloading local LLM)."""
        results = []
        for fid in finding_ids:
            result = await self.triage_finding(fid)
            results.append(result)
            await asyncio.sleep(0.5)  # Gentle pacing
        return results

    # ─── Internal Methods ──────────────────────────────────────────────────

    def _build_triage_prompt(self, finding: Finding) -> str:
        return f"""You are a senior security analyst. Analyze this vulnerability finding and determine if it is a true positive or false positive.

## Finding Details
- **Title**: {finding.title}
- **Severity**: {finding.severity}
- **Category**: {finding.category}
- **Description**: {finding.description[:1000]}
- **Evidence**: {finding.evidence[:1000]}

## Instructions
Respond in JSON format:
{{
  "is_true_positive": true/false,
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation",
  "severity_adjustment": "none|upgrade|downgrade",
  "recommended_severity": "critical|high|medium|low|info"
}}"""

    def _build_poc_prompt(self, finding: Finding) -> str:
        return f"""You are a security researcher. Write a clean, professional Proof-of-Concept (PoC) report in Markdown format for this vulnerability.

## Finding
- **Title**: {finding.title}
- **Severity**: {finding.severity}
- **Category**: {finding.category}
- **Description**: {finding.description[:1500]}
- **Evidence**: {finding.evidence[:1500]}
- **Solution**: {finding.solution[:500]}

## Report Structure
1. Executive Summary
2. Technical Details
3. Steps to Reproduce
4. Impact Assessment
5. Remediation Recommendations

Write the report now:"""

    async def _chat_completion(self, prompt: str) -> str:
        """Call the OpenAI-compatible chat completion endpoint.

        Serialised via ``_inference_semaphore`` and gated on:
          1. The global resource governor (pauses when host is under pressure)
          2. The module-level circuit breaker (blocks after 3 consecutive failures)
        """
        from core.resource_governor import system_healthy
        await system_healthy.wait()

        ctx = PolicyContext(user_id=None, workspace_id=None, tenant_id=None, global_scope=True)
        estimated_tokens = len(prompt) // 4
        
        eval_result = await circuit_breaker.evaluate(ctx, requested_tokens=estimated_tokens)
        if not eval_result.allowed:
            raise RuntimeError(f"Circuit breaker OPEN — LLM requests blocked: {eval_result.reason}")

        async with self._inference_semaphore:
            try:
                async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                    resp = await client.post(
                        f"{self._endpoint}/chat/completions",
                        json={
                            "model": self._model,
                            "messages": [
                                {"role": "system", "content": "You are an expert security analyst."},
                                {"role": "user", "content": prompt},
                            ],
                            "temperature": 0.3,
                            "max_tokens": 2000,
                            "keep_alive": 0,
                            "options": {
                                "num_ctx": 16384
                            }
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    
                    # Record usage after success
                    actual_tokens = data.get("usage", {}).get("total_tokens", estimated_tokens + 500)
                    await circuit_breaker.record(ctx, actual_tokens, cost=0.0) # local LLM = 0 cost
                    
                    result = data["choices"][0]["message"]["content"]
                    return result
            except Exception as e:
                # Basic failure handling
                await circuit_breaker.trip(ctx, f"HTTP Error: {str(e)}")
                raise

    def _parse_triage_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON verdict from LLM response."""
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass

        return {
            "is_true_positive": True,
            "is_false_positive": False,
            "confidence": 0.5,
            "reasoning": response[:500],
            "severity_adjustment": "none",
        }

    async def generate_node_summary(self, target_id: str, db_session) -> str:
        """
        Generate executive risk summary for a target node using the local LLM.
        """
        target = await db_session.get(Target, target_id)
        if not target:
            return "Target not found."

        dlp_query = await db_session.execute(
            select(DLPFinding)
            .join(CrawledURL, DLPFinding.crawled_url_id == CrawledURL.id)
            .where(CrawledURL.target_id == target_id)
        )
        dlp_findings = dlp_query.scalars().all()
        dlp_data = [
            {
                "type": df.finding_type,
                "value": df.value,
                "context": df.context,
                "compliance": df.compliance_tags
            }
            for df in dlp_findings
        ]

        node_data = {
            "target_id": target.id,
            "host": target.host,
            "risk_score": target.risk_score,
            "tech_stack": target.tech_stack,
            "known_cves": target.known_cves,
            "dlp_findings": dlp_data
        }

        node_data_str = json.dumps(node_data, indent=2)
        prompt = f"<|think|>\nAnalyze the following host security telemetry and draft a concise executive risk summary. Outline the main vectors of exposure and compliance implications.\n\n```json\n{node_data_str}\n```"

        url = DEFAULT_OLLAMA_GENERATE_URL
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": 0,
            "options": {
                "num_ctx": 16384
            }
        }

        try:
            from core.resource_governor import system_healthy
            await system_healthy.wait()

            ctx = PolicyContext(user_id=None, workspace_id=None, tenant_id=None, global_scope=True)
            estimated_tokens = len(prompt) // 4
            eval_result = await circuit_breaker.evaluate(ctx, requested_tokens=estimated_tokens)
            if not eval_result.allowed:
                return f"Circuit breaker OPEN — LLM requests blocked: {eval_result.reason}"

            async with self._inference_semaphore:
                async with httpx.AsyncClient(timeout=120.0) as client:
                    resp = await client.post(url, json=payload)
                    resp.raise_for_status()
                    result_json = resp.json()
                    
                    actual_tokens = result_json.get("eval_count", estimated_tokens) + result_json.get("prompt_eval_count", estimated_tokens)
                    await circuit_breaker.record(ctx, actual_tokens, cost=0.0)
                    
                    raw_response = result_json.get("response", "")

                    cleaned_response = re.sub(r"<\|think\|>.*?</\|think\|>", "", raw_response, flags=re.DOTALL)
                    cleaned_response = cleaned_response.replace("<|think|>", "").replace("</think>", "").strip()
                    return cleaned_response
        except Exception as e:
            ctx = PolicyContext(user_id=None, workspace_id=None, tenant_id=None, global_scope=True)
            await circuit_breaker.trip(ctx, f"HTTP Error: {str(e)}")
            logger.error("AI node summary generation failed for target %s: %s", target_id, e)
            return f"Failed to generate AI summary: {str(e)}"

    async def generate_state_machine(self, traffic_sequence: list) -> str:
        """
        Analyze a sequence of HTTP requests/responses and generate a Mermaid.js state-machine map.
        """
        if not await self.check_availability():
            return "graph TD;\n    A[Start] --> B[LLM Offline];"

        seq_str = ""
        for i, item in enumerate(traffic_sequence, start=1):
            method = item.get("method", "GET")
            url = item.get("url", "")
            status = item.get("status_code")
            status_str = f" ({status})" if status is not None else ""
            seq_str += f"{i}. {method} {url} ->{status_str}\n"

        prompt = f"""You are an expert web application architect. Analyze the following chronological traffic sequence of an authenticated session and map its sequential business logic.

Traffic Sequence:
{seq_str}

Generate a visual state-machine map representing the business logic flow as a standard, raw Mermaid.js flowchart graph (using 'graph TD' syntax).
Examples:
graph TD;
    A[GET /login] -->|200| B(POST /login);
    B -->|302| C(GET /dashboard);

Constraints:
1. Output ONLY the raw Mermaid.js code.
2. Do NOT wrap it in markdown code blocks (e.g. do not use ```mermaid).
3. Do NOT include any conversational introduction, explanation, or notes.
4. Output the flowchart directly starting with 'graph TD'.
"""
        try:
            raw_response = await self._chat_completion(prompt)
            cleaned = raw_response.strip()

            if cleaned.startswith("```"):
                lines = cleaned.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                cleaned = "\n".join(lines).strip()

            cleaned = re.sub(r"<\|think\|>.*?</\|think\|>", "", cleaned, flags=re.DOTALL)
            cleaned = cleaned.replace("<|think|>", "").replace("</think>", "").strip()
            return cleaned
        except Exception as e:
            logger.error("Failed to generate state machine graph: %s", e)
            return "graph TD;\n    A[Start] --> B[Generation Error];"

    @property
    def config(self) -> Dict[str, Any]:
        return {
            "endpoint": self._endpoint,
            "model": self._model,
            "available": self._available,
        }

# Global singleton
ai_triage = AITriageEngine()
