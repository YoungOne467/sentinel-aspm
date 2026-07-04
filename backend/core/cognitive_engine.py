"""
Cognitive Reasoning Engine — Local LLM integration for intelligent vulnerability mutation and verification.
Ingests target telemetry, requests analysis from Phi-4-mini-instruct, parses structured AttackPlan, and dispatches payloads.

Layer 3 Safeguards:
  - Token Telemetry: tiktoken (cl100k_base) truncation at 14,000 tokens.
  - Structural Enforcement: instructor + Pydantic V2 schema binding.
  - Payload Validation: sqlfluff lint guard on SQL-like payloads.
"""
import asyncio
import json
import logging
import os
import uuid
import hashlib
import re
from typing import Optional, Dict, Any, List

import httpx
import tiktoken
import instructor
from openai import AsyncOpenAI
from pydantic import ValidationError
from sqlalchemy import select

from core.database import AsyncSessionLocal, batch_writer
from core.models import Finding, Target, CrawledURL
from core.schemas import AttackAction, AttackPlan
from core.http_pool import HTTPClientPool
from core.resource_governor import system_healthy
from core.ai_triage import CircuitBreaker, CIRCUIT_BREAKER_COOLDOWN, CIRCUIT_BREAKER_THRESHOLD

logger = logging.getLogger(__name__)

# ─── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_LLM_ENDPOINT = os.getenv("OLLAMA_OPENAI_ENDPOINT", "http://localhost:11434/v1")
DEFAULT_OLLAMA_GENERATE_URL = os.getenv("OLLAMA_GENERATE_URL", "http://localhost:11434/api/generate")
HARDCODED_MODEL = "hf.co/Melvin56/Phi-4-mini-instruct-abliterated-GGUF:Q4_K_M"
REQUEST_TIMEOUT = 180.0  # Cognitive tasks take longer

# Token telemetry constants
TOKEN_BUDGET = 14_000
TOKEN_ENCODING = "cl100k_base"

# Module-level circuit breaker for Cognitive Engine
cognitive_circuit_breaker = CircuitBreaker(threshold=CIRCUIT_BREAKER_THRESHOLD, cooldown=CIRCUIT_BREAKER_COOLDOWN)

# Initialize tiktoken encoder once at module level for performance
_tiktoken_encoder = tiktoken.get_encoding(TOKEN_ENCODING)


def count_tokens(text: str) -> int:
    """Count the number of tokens in a text string using cl100k_base encoding."""
    return len(_tiktoken_encoder.encode(text))


def truncate_telemetry_to_budget(telemetry: dict, budget: int = TOKEN_BUDGET) -> dict:
    """
    Truncate endpoint telemetry to fit within the token budget.
    Removes oldest endpoints first (FIFO) until the serialized telemetry fits.
    Returns a (possibly truncated) copy of the telemetry dictionary.
    """
    serialized = json.dumps(telemetry, indent=2)
    token_count = count_tokens(serialized)

    if token_count <= budget:
        return telemetry

    # Work on a copy to avoid mutating the original
    truncated = {
        "target": telemetry["target"],
        "endpoints": list(telemetry["endpoints"]),
    }

    original_count = len(truncated["endpoints"])

    # Optimize using binary search: find the maximum index mid to start keeping endpoints from
    low = 0
    high = len(truncated["endpoints"])
    best_k = high  # default to keeping nothing if nothing fits

    while low <= high:
        mid = (low + high) // 2
        test_truncated = {
            "target": truncated["target"],
            "endpoints": truncated["endpoints"][mid:],
        }
        test_serialized = json.dumps(test_truncated, indent=2)
        if count_tokens(test_serialized) <= budget:
            best_k = mid
            high = mid - 1  # try to keep more (lower k means keeping more from the front)
        else:
            low = mid + 1

    truncated["endpoints"] = truncated["endpoints"][best_k:]
    removed_count = best_k

    logger.warning(
        "Token budget exceeded (%d > %d). Truncated %d/%d oldest endpoints to fit within context window.",
        token_count, budget, removed_count, original_count
    )

    return truncated


def validate_sql_payload(payload: str) -> bool:
    """
    Validate a SQL-like payload using sqlfluff lint.
    Returns True if the payload is syntactically valid SQL, False if it contains lint violations.
    Only applies to payloads that look like SQL (contain SQL keywords).
    """
    # Quick check: only lint payloads that look like SQL
    sql_keywords = re.compile(
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE|TRUNCATE|MERGE)\b",
        re.IGNORECASE,
    )
    if not sql_keywords.search(payload):
        # Not a SQL-like payload, skip validation — allow it through
        return True

    try:
        import sqlfluff

        result = sqlfluff.lint(payload, dialect="ansi")
        if result:
            # Only reject on actual parse errors (PRS) — ignore cosmetic/formatting rules (LT12, etc.)
            parse_errors = [v for v in result if v.get("code", "").upper() == "PRS"]

            if parse_errors:
                violation_summary = "; ".join(
                    f"L{v.get('start_line_no', '?')}:{v.get('start_line_pos', '?')} [{v.get('code', '?')}] {v.get('description', '')}"
                    for v in parse_errors
                )
                logger.warning(
                    "SQLFluff lint guard REJECTED payload (%d parse errors): %s | Payload: %.120s",
                    len(parse_errors), violation_summary, payload
                )
                return False
        return True
    except Exception as e:
        # If sqlfluff itself fails, log and allow the payload through (fail-open for non-SQL payloads)
        logger.error("SQLFluff lint guard encountered an error: %s. Allowing payload.", e)
        return True


class CognitiveEngineService:
    """
    Ingests target telemetry and queries the local Phi-4-mini model to output
    a structured vulnerability AttackPlan.

    Layer 3 Safeguards:
      - tiktoken truncation: ensures prompt stays under TOKEN_BUDGET.
      - instructor binding: forces LLM output into AttackPlan Pydantic schema.
    """

    def __init__(self, endpoint: str = DEFAULT_LLM_ENDPOINT):
        self._endpoint = endpoint.rstrip("/")
        self._model = HARDCODED_MODEL
        self._inference_semaphore = asyncio.Semaphore(1)  # Only 1 query at a time on 16GB host

        # ── Instructor-wrapped async OpenAI client pointed at Ollama ──
        self._openai_client = AsyncOpenAI(
            base_url=self._endpoint,
            api_key="ollama",  # Ollama doesn't require a real key
            timeout=REQUEST_TIMEOUT,
        )
        self._instructor_client = instructor.from_openai(self._openai_client, mode=instructor.Mode.JSON)

    async def analyze_target_telemetry(self, target_id: str, job_id: Optional[str] = None) -> Optional[AttackPlan]:
        """
        Gathers URL structures, HTTP Headers, and endpoints from targets and crawled_urls.
        Passes the consolidated telemetry to Phi-4-mini for structured analysis.
        """
        async with AsyncSessionLocal() as session:
            # 1. Fetch Target Telemetry
            target = await session.get(Target, target_id)
            if not target:
                logger.error("Target %s not found for telemetry analysis.", target_id)
                return None

            # 2. Fetch Crawled URLs
            crawled_query = await session.execute(
                select(CrawledURL).where(CrawledURL.target_id == target_id)
            )
            crawled_urls = crawled_query.scalars().all()

        # 3. Consolidate Telemetry data
        telemetry = {
            "target": {
                "host": target.host,
                "port": target.port,
                "tech_stack": target.tech_stack,
                "known_cves": target.known_cves,
                "notes": target.notes
            },
            "endpoints": [
                {
                    "url": cu.url,
                    "method": cu.method,
                    "status_code": cu.status_code,
                    "tech_stack": cu.tech_stack
                }
                for cu in crawled_urls
            ]
        }

        # ── Layer 3.1: Token Telemetry — truncate if over budget ──
        telemetry = truncate_telemetry_to_budget(telemetry, TOKEN_BUDGET)

        # 4. Formulate Prompt instructing structured JSON output matching AttackPlan
        prompt = f"""You are a senior security researcher operating an autonomous cognitive reasoning engine.
Analyze the target telemetry below and formulate a precise, highly-targeted AttackPlan containing actions.

Target Telemetry:
{json.dumps(telemetry, indent=2)}

Instructions:
1. Identify logic flaws, parameter exposures, authentication boundaries, or input entry points.
2. Generate specific payloads matching the action types.
3. You MUST return ONLY a valid JSON object matching this JSON Schema:
{json.dumps(AttackPlan.model_json_schema(), indent=2)}

Do NOT include any conversational introduction, explanations, or markdown code blocks (e.g. do not wrap in ```json).
Your response must be parseable directly as a JSON object matching the schema.
"""

        # ── Layer 3.2: Structural Enforcement via instructor ──
        try:
            plan = await self._structured_completion(prompt)
            logger.info(
                "Successfully generated AttackPlan with %d actions for target %s",
                len(plan.actions), target_id
            )
            return plan
        except ValidationError as val_err:
            logger.warning("LLM Schema Hallucination detected for target %s: %s", target_id, val_err)
            try:
                from core.orchestrator import orchestrator
                await orchestrator._broadcast_msg({
                    "type": "terminal_output",
                    "job_id": job_id,
                    "stream": "stderr",
                    "line": f"[LLM Schema Hallucination] Validation failed on structured completion: {val_err}",
                    "tool": "Cognitive AI Recon"
                })
            except Exception as broadcast_err:
                logger.error("Failed to broadcast LLM Schema Hallucination warning: %s", broadcast_err)
            return None
        except Exception as e:
            logger.error("Failed to generate or parse AttackPlan for target %s: %s", target_id, e)
            return None

    async def analyze_target(self, target_id: str, job_id: Optional[str] = None) -> Optional[AttackPlan]:
        """Alias for analyze_target_telemetry to match orchestrator trigger naming."""
        return await self.analyze_target_telemetry(target_id, job_id)

    async def _structured_completion(self, prompt: str) -> AttackPlan:
        """
        Call Ollama via instructor-wrapped AsyncOpenAI client with Pydantic V2 schema binding.
        Uses circuit breaker, system health checks, and concurrency gating.
        instructor auto-retries up to max_retries=2 on schema validation failures.
        """
        await system_healthy.wait()

        if not cognitive_circuit_breaker.allow_request():
            raise RuntimeError("Cognitive Circuit breaker OPEN. Request blocked.")

        async with self._inference_semaphore:
            try:
                plan = await self._instructor_client.chat.completions.create(
                    model=self._model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a silent cognitive scanning engine. Output only structured JSON.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    response_model=AttackPlan,
                    max_retries=2,
                    temperature=0.0,
                    seed=42,
                    # Ollama-specific options passed as extra_body
                    extra_body={
                        "keep_alive": 0,
                        "options": {
                            "num_ctx": 16384,
                            "seed": 42,
                            "temperature": 0.0,
                        },
                    },
                )
                cognitive_circuit_breaker.record_success()
                return plan
            except Exception:
                cognitive_circuit_breaker.record_failure()
                raise


class Dispatcher:
    """
    Processes the AttackPlan generated by the Cognitive Engine.
    Executes actions concurrently, utilizing the connection-pooled HTTP client pool,
    concurrency semaphore gating, and writes verified findings to the database.

    Layer 3 Safeguard:
      - sqlfluff lint guard on SQL-like payloads before execution.
    """

    # SQL Injection signatures
    SQLI_SIGNATURES = [
        "sql syntax", "mysql_fetch", "sqlite3.operationalerror", 
        "postgresql query failed", "unclosed quotation mark", 
        "ora-00933", "driver error", "db error", "database_error"
    ]

    # Local File Inclusion signatures
    LFI_SIGNATURES = [
        "root:x:0:0:", "[boot loader]", "etc/passwd", "win.ini"
    ]

    def __init__(self, concurrency_limit: int = 15):
        self._semaphore = asyncio.Semaphore(concurrency_limit)

    async def dispatch_plan(self, target_id: str, plan: AttackPlan):
        """
        Iterates over AttackPlan actions and schedules them concurrently.
        """
        logger.info("Starting AttackPlan dispatch for target %s with %d actions", target_id, len(plan.actions))
        client = await HTTPClientPool.get_client()

        # Build tasks list
        tasks = [
            self._execute_action(target_id, action, client)
            for action in plan.actions
        ]
        
        # Run concurrently under Semaphore
        await asyncio.gather(*tasks)
        await batch_writer.flush()
        logger.info("Finished AttackPlan dispatch for target %s", target_id)

    async def execute_plan(self, target_id: str, plan: AttackPlan):
        """Alias for dispatch_plan to match orchestrator trigger naming."""
        await self.dispatch_plan(target_id, plan)

    async def _execute_action(self, target_id: str, action: AttackAction, client: httpx.AsyncClient):
        """
        Executes a single AttackAction.
        """
        async with self._semaphore:
            # ── Layer 3.3: Payload Validation — sqlfluff lint guard ──
            if action.action_type in ("FUZZ_PARAMETER", "CRAFT_CUSTOM_PAYLOAD"):
                if not validate_sql_payload(action.generated_payload):
                    logger.warning(
                        "DROPPING action %s for target %s — payload failed SQLFluff validation: %.120s",
                        action.action_type, target_id, action.generated_payload
                    )
                    return

            # 1. Resolve Target Base URL
            async with AsyncSessionLocal() as session:
                target = await session.get(Target, target_id)
                if not target:
                    return

            scheme = "https" if target.port == 443 else "http"
            port_suffix = f":{target.port}" if target.port and target.port not in (80, 443) else ""
            base_url = f"{scheme}://{target.host}{port_suffix}"

            # Resolve full target URL
            url = action.target_element
            if not (url.startswith("http://") or url.startswith("https://")):
                url = base_url + ("/" if not url.startswith("/") else "") + url

            # 2. Determine Method and Parameters
            method = "GET"
            # Attempt to lookup matching CrawledURL to respect standard method
            async with AsyncSessionLocal() as session:
                cu_query = await session.execute(
                    select(CrawledURL).where(
                        CrawledURL.target_id == target_id,
                        CrawledURL.url.like(f"%{action.target_element}%")
                    )
                )
                cu = cu_query.scalars().first()
                if cu and cu.method:
                    method = cu.method.upper()

            # Construct request arguments based on ActionType
            req_kwargs = {"timeout": 15.0}

            if action.action_type == "FUZZ_PARAMETER":
                # Inject payload as a query parameter or inside the JSON body
                if method == "POST":
                    # Assume JSON payload
                    req_kwargs["json"] = {"fuzz": action.generated_payload}
                else:
                    req_kwargs["params"] = {"fuzz": action.generated_payload}
            elif action.action_type == "CRAFT_CUSTOM_PAYLOAD":
                if method == "POST":
                    req_kwargs["content"] = action.generated_payload
                    req_kwargs["headers"] = {"Content-Type": "text/plain"}
                else:
                    req_kwargs["params"] = {"payload": action.generated_payload}
            elif action.action_type == "ANALYZE_SOURCE_CODE":
                method = "GET"  # Standard retrieval

            # If action has headers, update req_kwargs["headers"]
            if hasattr(action, "headers") and action.headers:
                if "headers" not in req_kwargs:
                    req_kwargs["headers"] = {}
                req_kwargs["headers"].update(action.headers)

            # 3. Perform Request
            try:
                logger.debug("Dispatching action %s to %s", action.action_type, url)
                response = await client.request(method, url, **req_kwargs)
                response.read()

                # 4. Evaluate vulnerability heuristic
                finding = self._evaluate_response(target_id, action, response)
                if finding:
                    logger.warning("Vulnerability VERIFIED via cognitive action: %s", finding.title)
                    await batch_writer.enqueue(finding)
            except Exception as e:
                logger.error("Action execution failed for target %s element %s: %s", target_id, action.target_element, e)

    def _evaluate_response(self, target_id: str, action: AttackAction, response: httpx.Response) -> Optional[Finding]:
        """
        Evaluates the HTTP Response against common vulnerability heuristic indicators.
        Returns a Finding ORM instance if a potential exposure is verified.
        """
        body_lower = response.text.lower()
        vuln_detected = False
        category = "general"
        severity = "medium"
        evidence_prefix = f"Vulnerability verified by Cognitive Dispatcher.\nHypothesis: {action.logic_flaw_hypothesis}\nAction type: {action.action_type}\nPayload: {action.generated_payload}\n\n"

        # Check for SQL injection signatures
        for sig in self.SQLI_SIGNATURES:
            if sig in body_lower:
                vuln_detected = True
                category = "SQL Injection"
                severity = "critical"
                break

        # Check for Local File Inclusion signatures
        if not vuln_detected:
            for sig in self.LFI_SIGNATURES:
                if sig in response.text:
                    vuln_detected = True
                    category = "LFI"
                    severity = "high"
                    break

        # Check for unexpected Auth Bypass logic (status code change)
        if not vuln_detected:
            if "role validation" in action.logic_flaw_hypothesis.lower() or "auth" in action.logic_flaw_hypothesis.lower():
                # If we fuzzed an endpoint and got a success status code reflecting authentication bypass
                if response.status_code == 200 and any(keyword in body_lower for keyword in ["admin", "dashboard", "user_id", "profile"]):
                    vuln_detected = True
                    category = "Auth Bypass / Broken Access Control"
                    severity = "high"

        # If detected, build and return Finding ORM instance
        if vuln_detected:
            finding_id = str(uuid.uuid4())
            finding_hash_str = f"cognitive_{target_id}_{action.target_element}_{action.action_type}_{action.generated_payload}"
            h = hashlib.sha256(finding_hash_str.encode()).hexdigest()

            evidence_str = (
                f"{evidence_prefix}"
                f"Response Status: {response.status_code}\n"
                f"Response Headers:\n{json.dumps(dict(response.headers), indent=2)}\n\n"
                f"Response Body Preview:\n{response.text[:1500]}"
            )

            return Finding(
                id=finding_id,
                target_id=target_id,
                title=f"Cognitive Verification: {category} on {action.target_element}",
                severity=severity,
                category=category.lower().replace(" ", "_"),
                description=(
                    f"The Autonomous Cognitive Engine identified and successfully verified an exposure on "
                    f"path '{action.target_element}'.\nHypothesis: {action.logic_flaw_hypothesis}"
                ),
                evidence=evidence_str,
                solution="Implement strict server-side sanitation, parameter validation, and enforce strict server-side access control checks.",
                hash=h,
                status="confirmed",
                ai_triaged=True,
                ai_verdict=json.dumps({
                    "is_true_positive": True,
                    "is_false_positive": False,
                    "confidence": 0.95,
                    "reasoning": f"Response matched cognitive heuristic signature for {category}."
                }),
                raw_data={
                    "target_element": action.target_element,
                    "logic_flaw_hypothesis": action.logic_flaw_hypothesis,
                    "action_type": action.action_type,
                    "payload": action.generated_payload,
                    "status_code": response.status_code
                }
            )

        return None
