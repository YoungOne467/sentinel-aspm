from pydantic import BaseModel, ConfigDict, field_validator
from pydantic.alias_generators import to_camel
from typing import List, Optional, Dict, Any, Literal
from datetime import datetime
from core.request_context import sanitize_scan_headers

# ─── Base Configuration for Pydantic V2 ────────────────────────────────────────

class BaseModelV2(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )

# ─── Target Schemas ───────────────────────────────────────────────────────────

class TargetCreate(BaseModelV2):
    name: str
    host: str
    port: Optional[int] = None
    tags: Optional[List[str]] = []
    notes: Optional[str] = ""

class TargetUpdate(BaseModelV2):
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None

class TargetResponse(BaseModelV2):
    id: str
    name: str
    host: str
    port: Optional[int] = None
    tags: List[str] = []
    notes: str = ""
    tech_stack: List[str] = []
    risk_score: float = 0.0
    known_cves: List[str] = []
    created_at: datetime
    updated_at: Optional[datetime] = None

# ─── Job Schemas ──────────────────────────────────────────────────────────────

class JobCreate(BaseModelV2):
    target_id: str
    scan_profile: str

class JobResponse(BaseModelV2):
    id: str
    target_id: str
    tool_name: str
    command: str
    status: str
    exit_code: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

# ─── Finding Schemas ──────────────────────────────────────────────────────────

class FindingUpdate(BaseModelV2):
    status: Optional[Literal["open", "confirmed", "false_positive", "resolved"]] = None

class FindingResponse(BaseModelV2):
    id: str
    job_id: Optional[str] = None
    target_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    category: str
    description: str
    evidence: str
    solution: str
    status: Literal["open", "confirmed", "false_positive", "resolved"]
    ai_triaged: bool
    first_seen: datetime
    last_seen: datetime

# ─── Scope Rule Schemas ────────────────────────────────────────────────────────

class ScopeRuleCreate(BaseModelV2):
    rule_type: Literal["include", "exclude"]
    pattern_type: Literal["domain", "wildcard", "cidr", "regex"]
    pattern: str
    description: Optional[str] = ""

class ScopeRuleResponse(BaseModelV2):
    id: str
    rule_type: str
    pattern_type: str
    pattern: str
    description: str
    active: bool
    created_at: datetime

# ─── System Health Schemas ─────────────────────────────────────────────────────

class SystemMetrics(BaseModelV2):
    cpu_percent: float
    memory_percent: float
    memory_total_mb: int
    memory_available_mb: int

class HealthResponse(BaseModelV2):
    status: str
    version: str
    active_jobs: int
    ws_connections: int
    system: Optional[SystemMetrics] = None

# ─── Scan Request Schemas ──────────────────────────────────────────────────────

class ScanRequest(BaseModelV2):
    url: str
    intensity: Literal["stealth", "normal", "aggressive", "extreme"]
    scan_headers: Optional[Dict[str, str]] = None
    auth_profiles: Optional[Dict[str, Any]] = None
    openapi_url: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    penetration_depth: Optional[str] = None
    state_changing: Optional[bool] = None

    @field_validator("scan_headers", mode="before")
    @classmethod
    def sanitize_headers(cls, v):
        if v is not None:
            return sanitize_scan_headers(v)
        return v

    @field_validator("auth_profiles", mode="before")
    @classmethod
    def sanitize_profiles(cls, v):
        if v is not None:
            from core.auth_profiles import sanitize_auth_profiles
            return sanitize_auth_profiles(v)
        return v

# ─── Exploit/AI Request Schemas ────────────────────────────────────────────────

class ExploitTestRequest(BaseModelV2):
    target_url: Optional[str] = None
    vuln_type: Optional[str] = None
    base_payload: Optional[str] = None
    vector: Optional[str] = None
    post_action: Optional[str] = None
    use_ai: Optional[bool] = True
    surface_node: Optional[str] = None
    auth_profile: Optional[str] = None
    
    url: Optional[str] = None
    intensity: Optional[str] = None
    scan_headers: Optional[Dict[str, str]] = None
    auth_profiles: Optional[Dict[str, Any]] = None
    openapi_url: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    penetration_depth: Optional[str] = None
    state_changing: Optional[bool] = None

class ExploitActionRequest(BaseModelV2):
    action: str
    command: Optional[str] = None
    confirm: bool = False

class ExploitStopRequest(BaseModelV2):
    execution_id: Optional[str] = None

class OASTSettingsUpdate(BaseModelV2):
    domain: str
    token: Optional[str] = ""
    provider: Optional[str] = "private-interactsh"

class IngestRequest(BaseModelV2):
    target_id: str
    job_id: Optional[str] = None
    raw_output: str
    output_format: str = "json"

class AITriageRequest(BaseModelV2):
    finding_ids: List[str]

class LLMConfigUpdate(BaseModelV2):
    endpoint: Optional[str] = None
    model: Optional[str] = None

# ─── Autonomous Cognitive Engine Schemas ─────────────────────────────────────

class AttackAction(BaseModelV2):
    target_element: str
    logic_flaw_hypothesis: str
    action_type: Literal["FUZZ_PARAMETER", "CRAFT_CUSTOM_PAYLOAD", "ANALYZE_SOURCE_CODE"]
    generated_payload: str
    headers: Optional[Dict[str, str]] = None

class AttackPlan(BaseModelV2):
    actions: List[AttackAction]

# ─── Evasion & Remediation Schemas ─────────────────────────────────────────────

class RemediationRequest(BaseModelV2):
    finding_id: str

class EvasionSettingsUpdate(BaseModelV2):
    custom_headers: Optional[Dict[str, str]] = None
    sqli_strategy: Optional[str] = None
    xss_strategy: Optional[str] = None
    lfi_strategy: Optional[str] = None

