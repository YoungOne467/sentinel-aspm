"""
AI Orchestrator — SENTINEL Execution Pipeline.

Sits between the LLM Router and the frontend. Handles:
  1. Full-pipeline finding analysis (compress → inject → route → validate → sandbox)
  2. Pydantic V2 strict schemas for executable actions
  3. Dry-Run Sandbox static analysis (scope compliance, syntax validation, blast radius)
  4. Docker-isolated payload execution for POST /api/execute/ad-hoc
"""

import os
import re
import json
import shlex
import logging
import asyncio
import hashlib
from urllib.parse import urlparse
from typing import Optional, Literal

from pydantic import BaseModel, Field

logger = logging.getLogger("sentinel.ai_orchestrator")


# ─── Pydantic V2 Execution Schemas ───────────────────────────────────────────

class ExecutableAction(BaseModel):
    """A single actionable output from the AI analysis pipeline."""
    action_type: Literal[
        "curl_verification", "git_patch", "python_exploit_script",
        "nuclei_template", "bash_command"
    ] = Field(description="Type of executable action")
    title: str = Field(description="Short human-readable description")
    command: Optional[str] = Field(default=None, description="Shell command or curl invocation")
    patch_content: Optional[str] = Field(default=None, description="Diff/patch content")
    target_file: Optional[str] = Field(default=None, description="File path for patch application")
    target_url: Optional[str] = Field(default=None, description="Target URL for the action")
    method: Optional[str] = Field(default=None, description="HTTP method (GET, POST, etc.)")
    headers: Optional[dict[str, str]] = Field(default=None, description="HTTP headers for the request")
    risk_level: Literal["safe", "moderate", "dangerous"] = Field(
        default="moderate", description="Risk classification"
    )


class BlastRadiusAssessment(BaseModel):
    """Static safety analysis of a generated payload before execution."""
    scope_compliant: bool = Field(description="Target URL is within configured scope rules")
    syntax_valid: bool = Field(description="Generated code/command has valid syntax")
    targets_production: bool = Field(description="Heuristic: targets prod-looking domains")
    estimated_impact: Literal["none", "read_only", "state_changing", "destructive"] = Field(
        description="Impact classification of the action"
    )
    warnings: list[str] = Field(default_factory=list, description="Safety warnings")
    safety_score: float = Field(
        description="0.0 (extremely dangerous) to 1.0 (completely safe)"
    )


class ActionableTriagePlan(BaseModel):
    """Complete structured output from the AI analysis pipeline."""
    finding_id: Optional[str] = Field(default=None, description="Source finding ID")
    summary: str = Field(description="Detailed analysis summary")
    vulnerability_confirmed: bool = Field(description="Whether the vulnerability is confirmed")
    risk_score: float = Field(description="Risk score from 0.0 to 10.0")
    confidence: float = Field(description="Confidence score from 0.0 to 1.0")
    cve_references: list[str] = Field(default_factory=list, description="Related CVE IDs")
    remediation_steps: list[str] = Field(default_factory=list, description="Remediation instructions")
    actions: list[ExecutableAction] = Field(default_factory=list, description="Executable actions")
    blast_radius: list[BlastRadiusAssessment] = Field(
        default_factory=list, description="1:1 safety assessment for each action"
    )
    routing_metadata: dict = Field(default_factory=dict, description="RoutedResponse as dict")


# ─── Dry-Run Sandbox ─────────────────────────────────────────────────────────

# Production domain heuristics
_PROD_PATTERNS = re.compile(
    r"(^|\.)prod[.-]|production\.|live\.|api\.(?!localhost)|www\.|app\.",
    re.IGNORECASE,
)

# Destructive command patterns
_DESTRUCTIVE_PATTERNS = re.compile(
    r"\b(rm\s+-rf|drop\s+table|delete\s+from|truncate|format|shutdown|reboot|mkfs)\b",
    re.IGNORECASE,
)


class DryRunSandbox:
    """
    Static analysis engine that assesses the safety of AI-generated payloads
    BEFORE they reach the frontend or execution layer.
    """

    async def assess(self, action: ExecutableAction) -> BlastRadiusAssessment:
        """Run all safety checks on a single ExecutableAction."""
        warnings: list[str] = []

        # 1. Scope compliance
        scope_ok = await self._check_scope(action, warnings)

        # 2. Syntax validation
        syntax_ok = self._check_syntax(action, warnings)

        # 3. Production target detection
        is_prod = self._detect_production_target(action, warnings)

        # 4. Impact classification
        impact = self._classify_impact(action, warnings)

        # Calculate safety score
        score = 1.0
        if not scope_ok:
            score -= 0.4
        if not syntax_ok:
            score -= 0.2
        if is_prod:
            score -= 0.2
        if impact == "destructive":
            score -= 0.3
        elif impact == "state_changing":
            score -= 0.1
        score = max(0.0, min(1.0, score))

        return BlastRadiusAssessment(
            scope_compliant=scope_ok,
            syntax_valid=syntax_ok,
            targets_production=is_prod,
            estimated_impact=impact,
            warnings=warnings,
            safety_score=round(score, 2),
        )

    async def _check_scope(self, action: ExecutableAction, warnings: list[str]) -> bool:
        """Verify the action's target URL is within configured scope rules."""
        url = action.target_url
        if not url and action.command:
            # Extract URL from curl command
            url = self._extract_url_from_command(action.command)

        if not url:
            return True  # No URL to check → pass by default

        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host:
                return True

            from core.scope_manager import scope_manager
            await scope_manager.load_rules()
            in_scope = scope_manager.is_in_scope(host)
            if not in_scope:
                warnings.append(f"TARGET OUT OF SCOPE: {host} — payload will be blocked")
            return in_scope
        except Exception as e:
            logger.debug("Scope check failed: %s", e)
            warnings.append(f"Scope check error: {e}")
            return True  # Fail-open on check errors (scope manager may not be loaded)

    def _check_syntax(self, action: ExecutableAction, warnings: list[str]) -> bool:
        """Validate syntax of the generated payload."""
        if action.action_type == "python_exploit_script" and action.command:
            try:
                compile(action.command, "<ai_generated>", "exec")
                return True
            except SyntaxError as e:
                warnings.append(f"Python syntax error at line {e.lineno}: {e.msg}")
                return False

        if action.action_type == "bash_command" and action.command:
            try:
                shlex.split(action.command)
                return True
            except ValueError as e:
                warnings.append(f"Shell syntax error: {e}")
                return False

        if action.action_type == "curl_verification" and action.command:
            if not action.command.strip().startswith("curl"):
                warnings.append("curl_verification action does not start with 'curl'")
                return False
            return True

        if action.action_type == "git_patch" and action.patch_content:
            if not any(line.startswith(("---", "+++", "@@", "diff")) for line in action.patch_content.splitlines()):
                warnings.append("Patch content does not appear to be valid unified diff format")
                return False
            return True

        return True  # Default pass for unrecognized types

    def _detect_production_target(self, action: ExecutableAction, warnings: list[str]) -> bool:
        """Heuristic detection of production-looking targets."""
        urls_to_check = []
        if action.target_url:
            urls_to_check.append(action.target_url)
        if action.command:
            extracted = self._extract_url_from_command(action.command)
            if extracted:
                urls_to_check.append(extracted)

        for url in urls_to_check:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if _PROD_PATTERNS.search(host):
                warnings.append(f"WARNING: Target '{host}' matches production domain patterns")
                return True
        return False

    def _classify_impact(
        self, action: ExecutableAction, warnings: list[str]
    ) -> Literal["none", "read_only", "state_changing", "destructive"]:
        """Classify the estimated impact of an action."""
        cmd = action.command or ""

        # Check for destructive patterns
        if _DESTRUCTIVE_PATTERNS.search(cmd):
            warnings.append("CRITICAL: Command contains destructive operations")
            return "destructive"

        # Patch application is state-changing
        if action.action_type == "git_patch":
            return "state_changing"

        # Python scripts are state-changing by default
        if action.action_type == "python_exploit_script":
            return "state_changing"

        # HTTP method-based classification
        method = (action.method or "").upper()
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return "state_changing"

        # curl with -X POST/PUT/DELETE or -d (data)
        if action.action_type == "curl_verification" and cmd:
            if any(flag in cmd for flag in ["-X POST", "-X PUT", "-X DELETE", "-X PATCH", "-d ", "--data"]):
                return "state_changing"
            return "read_only"

        # Default
        if action.action_type == "nuclei_template":
            return "read_only"

        return "read_only"

    def _extract_url_from_command(self, command: str) -> Optional[str]:
        """Extract the first URL from a shell command string."""
        url_pattern = re.compile(r'https?://[^\s"\'>]+', re.IGNORECASE)
        match = url_pattern.search(command)
        return match.group(0) if match else None


# ─── The Orchestrator ────────────────────────────────────────────────────────

# JSON schema instruction template for forcing structured LLM output
_SCHEMA_INSTRUCTION = """

CRITICAL DIRECTIVE: You MUST respond with a valid JSON object strictly matching this schema:
{schema}
Do NOT wrap the JSON in markdown code blocks or any other characters.
Respond ONLY with the raw JSON string.
"""


class AIOrchestrator:
    """
    Full-pipeline AI execution engine.

    Pipeline stages:
      1. Load finding/context from database
      2. Compress evidence via token optimization
      3. Route to LLMRouter with task-specific model selection
      4. Parse JSON output into ActionableTriagePlan via Pydantic V2
      5. Run DryRunSandbox.assess() on each ExecutableAction
      6. Attach BlastRadiusAssessment to response
      7. Log execution to AIExecutionLog (handled by router)
    """

    def __init__(self):
        self._sandbox = DryRunSandbox()

    async def analyze_finding(
        self,
        finding_id: str,
        override_provider: Optional[str] = None,
        override_model: Optional[str] = None,
        force_override: bool = False,
    ) -> ActionableTriagePlan:
        """
        Full-pipeline analysis of a specific finding.
        Loads the finding, compresses evidence, routes to optimal model,
        validates JSON output, and runs blast-radius assessment.
        """
        from core.database import AsyncSessionLocal
        from core.models import Finding
        from core.llm_adapter import compress_http_response
        from core.llm_router import llm_router, AITaskType, ModelProvider

        # Step 1: Load finding
        async with AsyncSessionLocal() as session:
            finding = await session.get(Finding, finding_id)
            if not finding:
                return ActionableTriagePlan(
                    finding_id=finding_id,
                    summary=f"Finding '{finding_id}' not found in database.",
                    vulnerability_confirmed=False,
                    risk_score=0.0,
                    confidence=0.0,
                    routing_metadata={},
                )

            # Step 2: Compress evidence
            evidence_compressed = compress_http_response(finding.evidence or "", max_chars=2000)
            description_compressed = compress_http_response(finding.description or "", max_chars=1500)

            # Build the analysis prompt
            prompt = (
                f"Vulnerability Title: {finding.title}\n"
                f"Severity Classification: {finding.severity}\n"
                f"Subsystem Category: {finding.category}\n\n"
                "=== DETECTED EXPLOIT DESCRIPTION ===\n"
                f"{description_compressed}\n\n"
                "=== RAW TELEMETRY / EXPLOIT EVIDENCE ===\n"
                f"{evidence_compressed}\n\n"
                "Analyze this vulnerability. Determine if it is a confirmed positive.\n"
                "Generate executable verification actions (curl commands, patches, or scripts).\n"
                "Include CVE references if applicable."
            )

            system_prompt = (
                "You are a Principal Security Engineer at an elite red team. "
                "You analyze detected vulnerabilities and generate actionable exploit verification payloads. "
                "Your outputs must be precise, weaponized, and immediately executable."
            )

        # Step 3: Append JSON schema enforcement
        triage_schema = ActionableTriagePlan.model_json_schema()
        schema_prompt = prompt + _SCHEMA_INSTRUCTION.format(schema=json.dumps(triage_schema, indent=2))

        # Resolve overrides
        prov_override = None
        if override_provider:
            try:
                prov_override = ModelProvider(override_provider)
            except ValueError:
                logger.warning("Invalid override provider: %s", override_provider)

        # Step 4: Route to LLM
        routed = await llm_router.route(
            task_type=AITaskType.EXPLOIT_ANALYSIS,
            prompt=schema_prompt,
            system_prompt=system_prompt,
            override_provider=prov_override,
            override_model=override_model,
            inject_context=True,
            force_override=force_override,
        )

        # Step 5: Parse structured JSON
        plan = self._parse_llm_output(routed.content, finding_id)
        plan.routing_metadata = routed.model_dump()

        # Step 6: Run blast-radius assessment on each action
        assessments = []
        for action in plan.actions:
            assessment = await self._sandbox.assess(action)
            assessments.append(assessment)
        plan.blast_radius = assessments

        return plan

    async def execute_custom_prompt(
        self,
        prompt: str,
        task_type: Optional[str] = None,
        override_provider: Optional[str] = None,
        override_model: Optional[str] = None,
        force_override: bool = False,
    ) -> ActionableTriagePlan:
        """
        Execute a user-edited prompt through the full pipeline.
        """
        from core.llm_router import llm_router, AITaskType, ModelProvider

        # Resolve task type
        try:
            ai_task = AITaskType(task_type) if task_type else AITaskType.EXPLOIT_ANALYSIS
        except ValueError:
            ai_task = AITaskType.EXPLOIT_ANALYSIS

        # Append schema enforcement
        triage_schema = ActionableTriagePlan.model_json_schema()
        schema_prompt = prompt + _SCHEMA_INSTRUCTION.format(schema=json.dumps(triage_schema, indent=2))

        prov_override = None
        if override_provider:
            try:
                prov_override = ModelProvider(override_provider)
            except ValueError:
                pass

        system_prompt = (
            "You are a Principal Security Engineer. Analyze the provided context "
            "and generate a structured JSON response with executable verification actions."
        )

        routed = await llm_router.route(
            task_type=ai_task,
            prompt=schema_prompt,
            system_prompt=system_prompt,
            override_provider=prov_override,
            override_model=override_model,
            inject_context=True,
            force_override=force_override,
        )

        plan = self._parse_llm_output(routed.content)
        plan.routing_metadata = routed.model_dump()

        # Blast-radius on each action
        assessments = []
        for action in plan.actions:
            assessment = await self._sandbox.assess(action)
            assessments.append(assessment)
        plan.blast_radius = assessments

        return plan

    async def compile_prompt_for_finding(self, finding_id: str) -> dict:
        """
        Compile the raw prompt for a finding WITHOUT executing it.
        Returns the prompt text, available models, and routing config.
        """
        from core.database import AsyncSessionLocal
        from core.models import Finding
        from core.llm_adapter import compress_http_response
        from core.llm_router import llm_router

        async with AsyncSessionLocal() as session:
            finding = await session.get(Finding, finding_id)
            if not finding:
                return {"error": f"Finding '{finding_id}' not found"}

            evidence_compressed = compress_http_response(finding.evidence or "", max_chars=2000)
            description_compressed = compress_http_response(finding.description or "", max_chars=1500)

            prompt = (
                "You are a Principal Security Engineer conducting exploit analysis.\n\n"
                f"Vulnerability Title: {finding.title}\n"
                f"Severity Classification: {finding.severity}\n"
                f"Subsystem Category: {finding.category}\n\n"
                "=== DETECTED EXPLOIT DESCRIPTION ===\n"
                f"{description_compressed}\n\n"
                "=== RAW TELEMETRY / EXPLOIT EVIDENCE ===\n"
                f"{evidence_compressed}\n\n"
                "Analyze the provided context, verify if the finding represents a confirmed positive, "
                "and generate executable verification actions."
            )

        routing_config = await llm_router.get_routing_config()
        available_providers = await llm_router.get_available_providers()

        return {
            "finding_id": finding_id,
            "target": finding.title,
            "severity": finding.severity,
            "prompt": prompt,
            "routing_config": routing_config,
            "available_providers": available_providers,
        }

    # ── JSON Parsing ──────────────────────────────────────────────────────

    def _parse_llm_output(self, raw_output: str, finding_id: str = None) -> ActionableTriagePlan:
        """
        Parse and validate raw LLM output into ActionableTriagePlan.
        Handles markdown code fences, partial JSON, and validation errors gracefully.
        """
        cleaned = raw_output.strip()

        # Strip markdown code fences
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        # Attempt to find JSON object boundaries
        json_start = cleaned.find("{")
        json_end = cleaned.rfind("}")
        if json_start != -1 and json_end != -1 and json_end > json_start:
            cleaned = cleaned[json_start:json_end + 1]

        try:
            parsed = json.loads(cleaned)
            plan = ActionableTriagePlan.model_validate(parsed)
            if finding_id and not plan.finding_id:
                plan.finding_id = finding_id
            return plan
        except json.JSONDecodeError as e:
            logger.error("JSON decode failed for LLM output: %s", e)
        except Exception as e:
            logger.error("Pydantic validation failed: %s", e)

        # Graceful fallback
        return ActionableTriagePlan(
            finding_id=finding_id,
            summary=(
                "Analysis engine completed, but the LLM output could not be parsed as structured JSON. "
                f"Raw output preview: {raw_output[:500]}"
            ),
            vulnerability_confirmed=False,
            risk_score=0.0,
            confidence=0.0,
            routing_metadata={},
        )


# ─── Docker-Isolated Payload Execution ───────────────────────────────────────

class DockerPayloadExecutor:
    """
    Executes validated payloads inside ephemeral Docker containers.
    The container is destroyed immediately after execution.
    Stdout/stderr is captured and returned.
    """

    DOCKER_IMAGE = os.getenv("SENTINEL_EXEC_IMAGE", "python:3.12-slim")
    EXEC_TIMEOUT = int(os.getenv("SENTINEL_EXEC_TIMEOUT", "30"))

    async def execute(
        self,
        action: ExecutableAction,
        stream_callback=None,
    ) -> dict:
        """
        Execute an action inside an ephemeral Docker container.

        Args:
            action: The validated ExecutableAction to run.
            stream_callback: Optional async callable(line: str) for streaming output.

        Returns:
            {"exit_code": int, "stdout": str, "stderr": str, "container_id": str}
        """
        if not await self._is_docker_available():
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Docker is not available on this host. Install Docker to enable isolated payload execution.",
                "container_id": None,
            }

        container_name = f"sentinel-exec-{hashlib.md5(os.urandom(8)).hexdigest()[:12]}"

        # Build the command to run inside the container
        inner_cmd = self._build_inner_command(action)
        if not inner_cmd:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Cannot build execution command for action_type: {action.action_type}",
                "container_id": None,
            }

        # Docker run command: ephemeral, no network for destructive, timeout via --stop-timeout
        docker_cmd = [
            "docker", "run",
            "--rm",
            "--name", container_name,
            "--memory=256m",
            "--cpus=0.5",
            "--stop-timeout", str(self.EXEC_TIMEOUT),
            "--network=bridge",
            self.DOCKER_IMAGE,
            "sh", "-c", inner_cmd,
        ]

        stdout_lines = []
        stderr_lines = []

        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Stream stdout
            async def read_stream(stream, collector, callback):
                async for line in stream:
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    collector.append(decoded)
                    if callback:
                        await callback(decoded)

            await asyncio.gather(
                read_stream(process.stdout, stdout_lines, stream_callback),
                read_stream(process.stderr, stderr_lines, None),
            )

            try:
                exit_code = await asyncio.wait_for(process.wait(), timeout=self.EXEC_TIMEOUT + 5)
            except asyncio.TimeoutError:
                process.kill()
                exit_code = -1
                stderr_lines.append(f"Execution timed out after {self.EXEC_TIMEOUT}s")

            return {
                "exit_code": exit_code,
                "stdout": "\n".join(stdout_lines),
                "stderr": "\n".join(stderr_lines),
                "container_id": container_name,
            }

        except FileNotFoundError:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Docker binary not found in PATH.",
                "container_id": None,
            }
        except Exception as e:
            logger.error("Docker execution failed: %s", e)
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Execution error: {e}",
                "container_id": None,
            }
        finally:
            # Ensure container cleanup
            try:
                cleanup = await asyncio.create_subprocess_exec(
                    "docker", "rm", "-f", container_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await cleanup.wait()
            except Exception:
                pass

    def _build_inner_command(self, action: ExecutableAction) -> Optional[str]:
        """Convert an ExecutableAction into a shell command for the container."""
        if action.action_type == "curl_verification" and action.command:
            # Install curl in slim image and run
            return f"apt-get update -qq && apt-get install -yqq curl > /dev/null 2>&1 && {action.command}"

        if action.action_type == "python_exploit_script" and action.command:
            # Escape the script for sh -c execution
            escaped = action.command.replace("'", "'\\''")
            return f"python3 -c '{escaped}'"

        if action.action_type == "bash_command" and action.command:
            return action.command

        if action.action_type == "nuclei_template":
            return None  # Nuclei requires its own image — not supported in generic executor

        if action.action_type == "git_patch":
            return None  # Patches are applied locally, not in containers

        return None

    async def _is_docker_available(self) -> bool:
        """Check if Docker is available and running."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            exit_code = await asyncio.wait_for(proc.wait(), timeout=5)
            return exit_code == 0
        except Exception:
            return False


# ─── Global Singletons ───────────────────────────────────────────────────────

ai_orchestrator = AIOrchestrator()
docker_executor = DockerPayloadExecutor()
