"""
SQLAlchemy ORM models for the Security Telemetry Dashboard.
Covers: Targets, Jobs, Findings, ScopeRules, FeedTemplates, JSFindings, InfraClusters.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, DateTime, Integer, Float, Boolean,
    ForeignKey, JSON, Index,
)
from sqlalchemy.orm import relationship
from core.database import Base


def gen_id() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─── Primary Models ───────────────────────────────────────────────────────────

class TenantScopedMixin:
    tenant_id = Column(String, nullable=False, default="default", server_default="default", index=True)
    workspace_id = Column(String, nullable=False, default="default", server_default="default", index=True)


class Target(TenantScopedMixin, Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=True)
    tags = Column(JSON, default=list)
    notes = Column(Text, default="")
    tech_stack = Column(JSON, default=list)
    risk_score = Column(Float, default=0.0)
    known_cves = Column(JSON, default=list)
    ai_triage_pending = Column(Boolean, default=True, nullable=False, server_default="1")
    ai_summary = Column(Text, nullable=True)
    patch_analysis = Column(Text, nullable=True)
    logic_map = Column(Text, nullable=True)
    session_state = Column(JSON, nullable=True)  # Playwright storageState (BYOS)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)

    jobs = relationship("Job", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")
    js_findings = relationship("JSFinding", back_populates="target", cascade="all, delete-orphan")
    crawled_urls = relationship("CrawledURL", back_populates="target", cascade="all, delete-orphan")
    discovered_subdomains = relationship("DiscoveredSubdomain", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")
    oob_canaries = relationship("OOBCanary", back_populates="target", cascade="all, delete-orphan")
    websocket_streams = relationship("WebSocketStream", back_populates="target", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_targets_created_at", "created_at"),
        Index("ix_targets_risk_score", "risk_score"),
    )


class Job(TenantScopedMixin, Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    tool_name = Column(String, nullable=False)
    command = Column(Text, nullable=False)
    status = Column(String, default="queued")  # queued, running, completed, failed, cancelled
    exit_code = Column(Integer, nullable=True)
    stdout = Column(Text, default="")
    stderr = Column(Text, default="")
    stdout_compressed = Column(Boolean, default=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now_utc)

    target = relationship("Target", back_populates="jobs")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")
    crawled_urls = relationship("CrawledURL", back_populates="job", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_jobs_status", "status"),
        Index("ix_jobs_target_id", "target_id"),
        Index("ix_jobs_created_at", "created_at"),
    )


class Finding(TenantScopedMixin, Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=gen_id)
    job_id = Column(String, ForeignKey("jobs.id"), nullable=True)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, default="info")  # critical, high, medium, low, info
    category = Column(String, default="general")
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    solution = Column(Text, default="")
    hash = Column(String, unique=True, nullable=False)
    status = Column(String, default="open")  # open, confirmed, false_positive, resolved
    first_seen = Column(DateTime, default=now_utc)
    last_seen = Column(DateTime, default=now_utc)
    raw_data = Column(JSON, nullable=True)
    ai_triaged = Column(Boolean, default=False)
    ai_verdict = Column(Text, nullable=True)
    is_new = Column(Boolean, default=True)

    target = relationship("Target", back_populates="findings")
    job = relationship("Job", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_hash", "hash"),
        Index("ix_findings_target_id", "target_id"),
        Index("ix_findings_category", "category"),
        Index("ix_findings_first_seen", "first_seen"),
    )


# ─── Scope Management ─────────────────────────────────────────────────────────

class ScopeRule(Base):
    __tablename__ = "scope_rules"

    id = Column(String, primary_key=True, default=gen_id)
    rule_type = Column(String, nullable=False)  # include, exclude
    pattern_type = Column(String, nullable=False)  # domain, wildcard, cidr, regex
    pattern = Column(String, nullable=False)
    description = Column(Text, default="")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)


# ─── Feed Sync Templates ──────────────────────────────────────────────────────

class FeedTemplate(Base):
    __tablename__ = "feed_templates"

    id = Column(String, primary_key=True, default=gen_id)
    source = Column(String, nullable=False)  # e.g., "nuclei-templates"
    template_id = Column(String, nullable=False)
    name = Column(String, nullable=False)
    severity = Column(String, default="info")
    tags = Column(JSON, default=list)
    file_path = Column(Text, nullable=True)
    last_updated = Column(DateTime, default=now_utc)
    raw_content = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_feed_source_tid", "source", "template_id", unique=True),
    )


# ─── JavaScript Analysis Findings ─────────────────────────────────────────────

class JSFinding(TenantScopedMixin, Base):
    __tablename__ = "js_findings"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    source_url = Column(Text, nullable=False)
    finding_type = Column(String, nullable=False)  # secret, endpoint, comment, api_key
    value = Column(Text, nullable=False)
    context = Column(Text, default="")
    confidence = Column(Float, default=0.5)
    created_at = Column(DateTime, default=now_utc)

    target = relationship("Target", back_populates="js_findings")

    __table_args__ = (
        Index("ix_js_target_type", "target_id", "finding_type"),
    )


# ─── Infrastructure Fingerprint Clusters ──────────────────────────────────────

class InfraCluster(Base):
    __tablename__ = "infra_clusters"

    id = Column(String, primary_key=True, default=gen_id)
    cluster_name = Column(String, nullable=False)
    fingerprint_type = Column(String, nullable=False)  # favicon_mmh3, tls_san, combined
    fingerprint_value = Column(String, nullable=False)
    members = Column(JSON, default=list)  # list of host strings
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc)

    __table_args__ = (
        Index("ix_infra_fingerprint", "fingerprint_type", "fingerprint_value"),
    )


# ─── Crawled URL Inventory ───────────────────────────────────────────────────

class CrawledURL(TenantScopedMixin, Base):
    __tablename__ = "crawled_urls"

    id = Column(String, primary_key=True, default=gen_id)
    job_id = Column(String, ForeignKey("jobs.id"), nullable=True)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    host = Column(String, nullable=False)
    url = Column(Text, nullable=False)
    method = Column(String, default="GET", nullable=False, server_default="GET")
    status_code = Column(Integer, nullable=True)
    has_alert = Column(Boolean, default=False)
    is_new = Column(Boolean, default=True)
    tech_stack = Column(JSON, default=list)
    risk_score = Column(Float, default=0.0)
    known_cves = Column(JSON, default=list)
    first_seen = Column(DateTime, default=now_utc)
    last_seen = Column(DateTime, default=now_utc)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)

    target = relationship("Target", back_populates="crawled_urls")
    job = relationship("Job", back_populates="crawled_urls")
    dlp_findings = relationship("DLPFinding", back_populates="crawled_url", cascade="all, delete-orphan")
    shadow_apis = relationship("ShadowAPI", back_populates="crawled_url", cascade="all, delete-orphan")
    discovered_parameters = relationship("DiscoveredParameter", back_populates="crawled_url", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="crawled_url", cascade="all, delete-orphan")
    oob_canaries = relationship("OOBCanary", back_populates="crawled_url", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_crawled_urls_target_id", "target_id"),
        Index("ix_crawled_urls_url", "url"),
    )


# ─── Discovered Subdomains & DLP findings ─────────────────────────────────────

class DiscoveredSubdomain(TenantScopedMixin, Base):
    __tablename__ = "discovered_subdomains"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    subdomain = Column(String, nullable=False)
    source = Column(String, nullable=False)  # subfinder, san, wayback
    first_seen = Column(DateTime, default=now_utc)
    last_seen = Column(DateTime, default=now_utc)
    is_new = Column(Boolean, default=True)
    risk_score = Column(Float, default=0.0)
    tech_stack = Column(JSON, default=list)

    target = relationship("Target", back_populates="discovered_subdomains")

    __table_args__ = (
        Index("ix_discovered_subdomains_target_id", "target_id"),
        Index("ix_discovered_subdomains_subdomain", "subdomain"),
    )


class DLPFinding(TenantScopedMixin, Base):
    __tablename__ = "dlp_findings"

    id = Column(String, primary_key=True, default=gen_id)
    crawled_url_id = Column(String, ForeignKey("crawled_urls.id"), nullable=False)
    finding_type = Column(String, nullable=False)  # PII, Credential, Internal URI
    value = Column(String, nullable=False)
    context = Column(Text, default="")
    compliance_tags = Column(JSON, default=list)  # ["GDPR"], ["PCI-DSS"]
    created_at = Column(DateTime, default=now_utc)

    crawled_url = relationship("CrawledURL", back_populates="dlp_findings")

    __table_args__ = (
        Index("ix_dlp_findings_crawled_url_id", "crawled_url_id"),
    )


class ShadowAPI(TenantScopedMixin, Base):
    __tablename__ = "shadow_apis"

    id = Column(String, primary_key=True, default=gen_id)
    crawled_url_id = Column(String, ForeignKey("crawled_urls.id"), nullable=False)
    route = Column(String, nullable=False)
    created_at = Column(DateTime, default=now_utc)

    crawled_url = relationship("CrawledURL", back_populates="shadow_apis")

    __table_args__ = (
        Index("ix_shadow_apis_crawled_url_id", "crawled_url_id"),
        Index("ix_shadow_apis_route", "route"),
        Index("ix_shadow_apis_unique_route", "crawled_url_id", "route", unique=True),
    )


class DiscoveredParameter(TenantScopedMixin, Base):
    __tablename__ = "discovered_parameters"

    id = Column(String, primary_key=True, default=gen_id)
    crawled_url_id = Column(String, ForeignKey("crawled_urls.id"), nullable=False)
    name = Column(String, nullable=False)
    source = Column(String, nullable=False)  # query_string, identifier, literal
    context = Column(Text, default="")
    confidence = Column(Float, default=0.5)
    created_at = Column(DateTime, default=now_utc)

    crawled_url = relationship("CrawledURL", back_populates="discovered_parameters")

    __table_args__ = (
        Index("ix_discovered_parameters_crawled_url_id", "crawled_url_id"),
        Index("ix_discovered_parameters_name", "name"),
        Index("ix_discovered_parameters_unique", "crawled_url_id", "name", "source", unique=True),
    )


class Vulnerability(TenantScopedMixin, Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=gen_id)
    crawled_url_id = Column(String, ForeignKey("crawled_urls.id"), nullable=True)
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    vuln_type = Column(String, nullable=False)
    severity = Column(String, default="medium")
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    sink = Column(String, nullable=True)
    payload = Column(Text, default="")
    source = Column(String, default="active_research_engine")
    raw_data = Column(JSON, nullable=True)
    status = Column(String, default="open")
    ai_triage_pending = Column(Boolean, default=True, nullable=False, server_default="1")
    ai_summary = Column(Text, nullable=True)
    ai_template = Column(Text, nullable=True)
    chained_from_vuln_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=now_utc)

    crawled_url = relationship("CrawledURL", back_populates="vulnerabilities")
    target = relationship("Target", back_populates="vulnerabilities")
    chained_from = relationship(
        "Vulnerability",
        primaryjoin="foreign(Vulnerability.chained_from_vuln_id) == Vulnerability.id",
        remote_side=[id],
        uselist=False,
    )

    __table_args__ = (
        Index("ix_vulnerabilities_crawled_url_id", "crawled_url_id"),
        Index("ix_vulnerabilities_target_id", "target_id"),
        Index("ix_vulnerabilities_type", "vuln_type"),
        Index("ix_vulnerabilities_severity", "severity"),
        Index("ix_vulnerabilities_status", "status"),
        Index("ix_vulnerabilities_created_at", "created_at"),
    )


class OOBCanary(TenantScopedMixin, Base):
    __tablename__ = "OOB_Canaries"

    id = Column(String, primary_key=True, default=gen_id)
    correlation_id = Column(String, nullable=False, unique=True)
    canary_domain = Column(String, nullable=False, unique=True)
    target_url = Column(Text, nullable=False)
    parameter = Column(String, nullable=False)
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    crawled_url_id = Column(String, ForeignKey("crawled_urls.id"), nullable=True)
    provider = Column(String, default="interactsh")
    oast_domain = Column(String, nullable=True)
    oast_private = Column(Boolean, default=False, nullable=False, server_default="0")
    oast_auth_configured = Column(Boolean, default=False, nullable=False, server_default="0")
    status = Column(String, default="pending")
    interaction_count = Column(Integer, default=0)
    raw_interactions = Column(JSON, default=list)
    created_at = Column(DateTime, default=now_utc)
    triggered_at = Column(DateTime, nullable=True)
    last_polled_at = Column(DateTime, nullable=True)

    target = relationship("Target", back_populates="oob_canaries")
    crawled_url = relationship("CrawledURL", back_populates="oob_canaries")

    __table_args__ = (
        Index("ix_oob_canaries_correlation_id", "correlation_id"),
        Index("ix_oob_canaries_domain", "canary_domain"),
        Index("ix_oob_canaries_status", "status"),
        Index("ix_oob_canaries_target_id", "target_id"),
    )


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    vuln_type = Column(String, index=True, nullable=False)
    status_code = Column(String, index=True, nullable=False)
    original_payload = Column(Text, nullable=False)
    winning_payload = Column(Text, nullable=False)
    ai_analysis = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now_utc)


class WebSocketStream(TenantScopedMixin, Base):
    __tablename__ = "websocket_streams"

    id = Column(String, primary_key=True, default=gen_id)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    url = Column(Text, nullable=False)
    direction = Column(String, nullable=False)  # "sent" or "received"
    payload = Column(Text, nullable=False)
    payload_schema = Column(JSON, nullable=True)
    dlp_finding_type = Column(String, nullable=True)
    dlp_finding_value = Column(String, nullable=True)
    compliance_tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=now_utc)

    target = relationship("Target", back_populates="websocket_streams")

    __table_args__ = (
        Index("ix_websocket_streams_target_id", "target_id"),
        Index("ix_websocket_streams_url", "url"),
    )


class ApexPipelineState(Base):
    __tablename__ = "apex_pipeline_states"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_url = Column(String, nullable=False)
    endpoint_path = Column(String, nullable=True)
    method = Column(String, default="GET")
    parameters = Column(Text, default="{}")
    headers = Column(Text, default="{}")
    generated_payloads = Column(Text, default="[]")
    pipeline_state = Column(String, default="cloud_ingested")  # 'cloud_ingested', 'payloads_generated', 'injection_complete', 'exploit_verified'
    oast_token = Column(String, nullable=True)
    verification_proof = Column(Text, default="{}")
    created_at = Column(DateTime, default=now_utc)

    __table_args__ = (
        Index("ix_apex_pipeline_states_target_url", "target_url"),
        Index("ix_apex_pipeline_states_state", "pipeline_state"),
        Index("ix_apex_pipeline_states_oast_token", "oast_token"),
    )


# ─── Configuration Settings & Encryption ──────────────────────────────────────

from sqlalchemy.types import TypeDecorator
from core.encryption_store import encryption_store

class EncryptedColumn(TypeDecorator):
    """Symmetric encryption at rest for sensitive SQLAlchemy fields."""
    impl = Text

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        # If it's a dict or list (for JSON columns), serialize first
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        return encryption_store.encrypt_string(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        decrypted = encryption_store.decrypt_string(value)
        # Attempt to parse as JSON if it looks like one, fallback to raw string
        if decrypted.startswith("{") or decrypted.startswith("["):
            try:
                return json.loads(decrypted)
            except Exception:
                pass
        return decrypted


class PlatformSettings(Base):
    __tablename__ = "platform_settings"

    id = Column(String, primary_key=True, default=gen_id)

    # AI Framework Keys — Core Providers
    openai_key = Column(EncryptedColumn, nullable=True)
    anthropic_key = Column(EncryptedColumn, nullable=True)
    ollama_base_url = Column(String, nullable=True)

    # AI Framework Keys — Extended Providers (2026 Matrix)
    deepseek_key = Column(EncryptedColumn, nullable=True)
    azure_ai_key = Column(EncryptedColumn, nullable=True)
    azure_ai_endpoint = Column(String, nullable=True)       # https://<resource>.openai.azure.com/
    google_ai_key = Column(EncryptedColumn, nullable=True)
    moonshot_key = Column(EncryptedColumn, nullable=True)    # Kimi/Moonshot AI
    vllm_base_url = Column(String, nullable=True)            # http://host:8000/v1 (OpenAI-compatible)

    # AI Routing Configuration — JSON overrides for the default routing matrix
    # Format: {"EXPLOIT_ANALYSIS": {"provider": "anthropic", "model": "claude-opus-4-20260601"}, ...}
    ai_routing_config = Column(JSON, nullable=True)

    # Scan Authentication
    custom_headers = Column(EncryptedColumn, nullable=True)  # JSON list of dicts: [{"key": "X-Custom", "value": "val"}]
    session_cookies = Column(EncryptedColumn, nullable=True)  # JSON list of dicts: [{"name": "sess", "value": "abc"}]

    # Upstream Routing
    upstream_proxy = Column(String, nullable=True)  # socks5://host:port or http://host:port
    user_agent = Column(Text, nullable=True)

    # Integrations
    jira_host = Column(String, nullable=True)
    jira_email = Column(String, nullable=True)
    jira_pat = Column(EncryptedColumn, nullable=True)
    github_pat = Column(EncryptedColumn, nullable=True)
    discord_webhook = Column(EncryptedColumn, nullable=True)
    slack_webhook = Column(EncryptedColumn, nullable=True)

    # Scan Controls
    max_concurrent_workers = Column(Integer, default=5, nullable=False, server_default="5")
    rate_limit_rps = Column(Integer, default=10, nullable=False, server_default="10")
    global_blacklist = Column(Text, default="")  # Comma-separated IPs/CIDRs

    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


# ─── AI Execution Audit Log ──────────────────────────────────────────────────

class AIExecutionLog(TenantScopedMixin, Base):
    """Immutable audit trail for every routed LLM call."""
    __tablename__ = "ai_execution_logs"

    id = Column(String, primary_key=True, default=gen_id)
    task_type = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False)
    model = Column(String, nullable=False)
    prompt_hash = Column(String, nullable=False)            # SHA-256 of the prompt (never store raw prompts)
    latency_ms = Column(Float, nullable=False)
    fallback_chain = Column(JSON, default=list)             # ["anthropic:claude-opus-4", "openai:gpt-5.5"]
    success = Column(Boolean, nullable=False, default=True)
    error_message = Column(Text, nullable=True)
    context_injected = Column(Boolean, default=False)
    cost_tier = Column(String, nullable=True)               # premium, standard, budget, local
    token_estimate = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=now_utc)

    __table_args__ = (
        Index("ix_ai_exec_log_task_type", "task_type"),
        Index("ix_ai_exec_log_provider", "provider"),
        Index("ix_ai_exec_log_created_at", "created_at"),
    )


class WorkspaceCapabilityApproval(TenantScopedMixin, Base):
    __tablename__ = "workspace_capability_approvals"

    id = Column(String, primary_key=True, default=gen_id)
    plugin_id = Column(String, nullable=False, index=True)
    capability = Column(String, nullable=False, index=True)
    approved_by = Column(String, nullable=False)
    approved_at = Column(DateTime, default=now_utc)


class UsageAttributionRecord(TenantScopedMixin, Base):
    __tablename__ = "usage_attribution_records"

    id = Column(String, primary_key=True, default=gen_id)
    execution_id = Column(String, nullable=False, index=True)
    scanner_id = Column(String, nullable=False, index=True)
    tokens_consumed = Column(Integer, default=0, nullable=False)
    infra_cost = Column(Float, default=0.0, nullable=False)
    token_cost = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=now_utc, index=True)


