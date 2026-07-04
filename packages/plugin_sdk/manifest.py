import os
import yaml
import json
import logging
import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from packages.plugin_sdk.interfaces import PluginCapabilityResolver, CapabilityDecision
from packages.security.providers import secret_chain
from packages.execution.docker import DockerRuntime
from packages.execution.interfaces import ExecutionResult
from packages.audit.emitter import audit_emitter
from packages.audit.events import PluginExecutionStartedEvent, PluginExecutionCompletedEvent

logger = logging.getLogger(__name__)

class ScannerRule(BaseModel):
    pattern: str
    severity: str = "medium"
    title: str = "Vulnerability Detected"
    description: str = ""
    solution: str = "Apply recommended patches."

class RuntimeConfig(BaseModel):
    image: str

class PluginManifest(BaseModel):
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    runtime: RuntimeConfig
    entrypoint: List[str] = Field(default_factory=list)
    environment: Dict[str, str] = Field(default_factory=dict)
    rules: List[ScannerRule] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    secrets: List[str] = Field(default_factory=list)
    signature: Optional[Dict[str, Any]] = None

class DeclarativeScanner:
    """Safely executes declarative CLI scanners using the ContainerRuntime and parsed via regular expression rules."""
    
    def __init__(self, manifest: PluginManifest, capability_resolver: PluginCapabilityResolver):
        self.manifest = manifest
        self.id = manifest.id
        self.name = manifest.name
        self.capability_resolver = capability_resolver
        self.runtime = DockerRuntime() # Hardcoded for Phase 2 interim, would be injected later

    def _sanitize_target(self, target: str) -> str:
        return re.sub(r"[;&|`$\n\r]", "", target).strip()

    async def _resolve_environment(self) -> Dict[str, str]:
        env = dict(self.manifest.environment)
        for secret_name in self.manifest.secrets:
            resolved = await secret_chain.resolve(secret_name)
            if resolved:
                # Typically, injected as an environment variable in all-caps
                env[secret_name.upper()] = resolved
            else:
                logger.warning(f"Failed to resolve declared secret {secret_name}")
        return env

    async def execute(
        self, 
        target: str, 
        tenant_id: str = "default", 
        workspace_id: Optional[str] = None, 
        execution_id: Optional[str] = None,
        contract_id: Optional[str] = None,
        scheduler_version: Optional[str] = None,
        node_version: Optional[str] = None
    ) -> ExecutionResult:
        """Safely executes the scanner binary inside the container runtime."""
        import uuid
        from packages.observability.telemetry import trace_execution_span
        
        exec_id = execution_id or str(uuid.uuid4())
        ws_id = workspace_id or "default-workspace"
        c_id = contract_id or "default-contract"
        sched_ver = scheduler_version or "1.0.0"
        node_ver = node_version or "1.0.0"
        
        # 1. Capability & Trust Validation
        manifest_dict = self.manifest.model_dump()
        signature_dict = manifest_dict.pop("signature", None)
        
        decision = await self.capability_resolver.validate(
            self.manifest.capabilities, 
            self.id, 
            manifest_data=manifest_dict, 
            signature_block=signature_dict
        )
        if not decision.allowed:
            logger.error(f"Execution of {self.name} blocked: {decision.reason}")
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Execution blocked: {decision.reason}",
                duration_ms=0
            )
            
        await audit_emitter.emit(
            PluginExecutionStartedEvent(
                name="PluginExecutionStarted",
                payload={
                    "plugin_id": self.id, 
                    "capabilities": self.manifest.capabilities,
                    "tenant_id": tenant_id,
                    "workspace_id": ws_id,
                    "execution_id": exec_id
                }
            ),
            actor="system"
        )
        
        # 2. Preparation
        safe_target = self._sanitize_target(target)
        args = [arg.replace("{{ target }}", safe_target) for arg in self.manifest.entrypoint]
        env = await self._resolve_environment()
        
        # 3. Execution via ContainerRuntime under a Trace Boundary
        runtime_type = self.runtime.__class__.__name__.replace("Runtime", "").lower()
        runtime_version = getattr(self.runtime, "version", "1.0.0")
        node_id = getattr(self.runtime, "node_id", "local-node")
        
        with trace_execution_span(
            tenant_id=tenant_id,
            workspace_id=ws_id,
            execution_id=exec_id,
            node_id=node_id,
            runtime_type=runtime_type,
            runtime_version=runtime_version,
            contract_id=c_id,
            scheduler_version=sched_ver,
            node_version=node_ver,
            plugin_id=self.id
        ):
            result: ExecutionResult = await self.runtime.execute(
                image=self.manifest.runtime.image, 
                command=args, 
                env=env, 
                capabilities=self.manifest.capabilities,
                tenant_id=tenant_id
            )
        
        await audit_emitter.emit(
            PluginExecutionCompletedEvent(
                name="PluginExecutionCompleted",
                payload={
                    "plugin_id": self.id, 
                    "exit_code": result.exit_code,
                    "tenant_id": tenant_id,
                    "workspace_id": workspace_id,
                    "execution_id": exec_id
                }
            ),
            actor="system"
        )
        
        # Record actual usage and write attribution record
        try:
            from packages.ai_governance.governance import budget_manager
            from core.database import AsyncSessionLocal
            
            # Extract actual token estimate from environment or manifest default
            actual_tokens = int(self.manifest.environment.get("ACTUAL_TOKENS", 5000))
            # Calculate infra cost from execution duration
            actual_infra_cost = (result.duration_ms / 1000.0) * 0.0001
            
            async with AsyncSessionLocal() as session:
                await budget_manager.record_actual_usage(
                    tenant_id=tenant_id,
                    workspace_id=ws_id,
                    execution_id=exec_id,
                    scanner_id=self.id,
                    actual_tokens=actual_tokens,
                    actual_infra_cost=actual_infra_cost,
                    token_rate=0.00002,
                    session=session
                )
                await session.commit()
        except Exception as usage_err:
            logger.error(f"Failed to record actual usage: {usage_err}")

        return result

    def parse_output(self, stdout: str, stderr: str = "") -> List[Dict[str, Any]]:
        findings = []
        combined_output = f"{stdout}\n{stderr}"
        
        for rule in self.manifest.rules:
            if not rule.pattern:
                continue
            try:
                matches = re.finditer(rule.pattern, combined_output, re.IGNORECASE)
                for match in matches:
                    matched_text = match.group(0)
                    findings.append({
                        "title": rule.title,
                        "severity": rule.severity,
                        "category": self.name,
                        "description": rule.description.replace("{match}", matched_text),
                        "evidence": f"Pattern matched: {matched_text}",
                        "solution": rule.solution,
                    })
            except Exception as e:
                logger.error(f"Regex matching error for pattern {rule.pattern}: {e}")
                
        return findings

class PluginLoader:
    def __init__(self, plugins_dir: str, capability_resolver: PluginCapabilityResolver):
        self.plugins_dir = plugins_dir
        self.capability_resolver = capability_resolver
        self.scanners: Dict[str, DeclarativeScanner] = {}
        self.load_scanners()

    def load_scanners(self):
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir, exist_ok=True)
            return

        for filename in os.listdir(self.plugins_dir):
            if filename.endswith((".yaml", ".yml", ".json")):
                full_path = os.path.join(self.plugins_dir, filename)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        if filename.endswith((".yaml", ".yml")):
                            data = yaml.safe_load(f)
                        else:
                            data = json.load(f)
                    
                    if not data:
                        continue
                    
                    # Validate schema via Pydantic v2
                    manifest = PluginManifest.model_validate(data)
                    scanner = DeclarativeScanner(manifest, self.capability_resolver)
                    self.scanners[scanner.id.lower()] = scanner
                    logger.info(f"Loaded pluggable scanner: {scanner.name}")
                except Exception as e:
                    logger.error(f"Failed to validate/load pluggable scanner config {filename}: {e}")

    def get_scanner(self, plugin_id: str) -> Optional[DeclarativeScanner]:
        return self.scanners.get(plugin_id.lower())

from packages.plugin_sdk.resolver import capability_resolver

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
PLUGINS_DIR = os.path.join(WORKSPACE_ROOT, "plugins")
plugin_loader = PluginLoader(PLUGINS_DIR, capability_resolver)
