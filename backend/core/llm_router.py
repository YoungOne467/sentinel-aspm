"""
Multi-Model Task Router — SENTINEL AI Orchestration Layer.

Routes AI tasks to optimal models based on a configurable routing matrix,
with automatic fallback chains, contextual auto-injection of session tokens
from the platform database, and cost guardrails to prevent waste.

2026 Model Landscape:
  - Claude Opus 4.8 (Anthropic) — best for complex agentic reasoning
  - GPT-5.5 (OpenAI) — stable terminal/shell automation
  - Gemini 3.1 Pro (Google) — 1M context, creative frontend
  - DeepSeek V4 Flash (DeepSeek) — cheapest batch classification
  - Kimi k2.6 (Moonshot) — budget fallback
  - DeepSeek V4 / Qwen3-32B — air-gapped open-weights deployment
"""

import os
import json
import time
import hashlib
import logging
from enum import Enum
from typing import Optional, Any
from dataclasses import dataclass, field

import httpx
from pydantic import BaseModel, Field
from cachetools import TTLCache

logger = logging.getLogger("sentinel.llm_router")


# ─── Enums ────────────────────────────────────────────────────────────────────

class AITaskType(str, Enum):
    """Task taxonomy for intelligent model routing."""
    # SENTINEL-specific tasks
    TRIAGE_COMPRESSION = "triage_compression"      # Fast context compression of HTTP logs
    EXPLOIT_ANALYSIS = "exploit_analysis"            # Deep reasoning for exploit verification
    REMEDIATION_GENERATION = "remediation_generation" # Patch/fix generation
    # General-purpose tasks (2026 matrix)
    CODE_REFACTOR = "code_refactor"
    TERMINAL_AUTOMATION = "terminal_automation"
    DOC_SUMMARIZATION = "doc_summarization"
    BATCH_CLASSIFICATION = "batch_classification"
    CREATIVE_FRONTEND = "creative_frontend"
    AIR_GAPPED_EXEC = "air_gapped_exec"


class ModelProvider(str, Enum):
    """Supported LLM provider backends."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    DEEPSEEK = "deepseek"
    OLLAMA = "ollama"
    LOCAL_VLLM = "local_vllm"    # OpenAI-compatible local vLLM clusters
    AZURE_AI = "azure_ai"        # Azure AI Foundry
    MOONSHOT = "moonshot"         # Kimi / Moonshot AI


class CostTier(str, Enum):
    """Model pricing classification."""
    PREMIUM = "premium"     # $15+/M input tokens (Opus, GPT-5.5)
    STANDARD = "standard"   # $2-15/M input tokens (Gemini Pro)
    BUDGET = "budget"       # <$2/M input tokens (DeepSeek Flash, Kimi)
    LOCAL = "local"         # No API cost (Ollama, vLLM)


# ─── Model Catalog ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ModelSpec:
    """Immutable specification of a model in the catalog."""
    provider: ModelProvider
    model_id: str
    display_name: str
    cost_tier: CostTier
    max_output_tokens: int = 4096
    context_window: int = 128_000
    supports_json_mode: bool = False
    supports_streaming: bool = True


# Canonical model catalog — the single source of truth for all known models.
MODEL_CATALOG: dict[str, ModelSpec] = {
    # ── Anthropic ──
    "claude-opus-4-20260601": ModelSpec(
        provider=ModelProvider.ANTHROPIC, model_id="claude-opus-4-20260601",
        display_name="Claude Opus 4.8", cost_tier=CostTier.PREMIUM,
        max_output_tokens=8192, context_window=200_000, supports_json_mode=True,
    ),
    # ── OpenAI ──
    "gpt-5.5": ModelSpec(
        provider=ModelProvider.OPENAI, model_id="gpt-5.5",
        display_name="GPT-5.5", cost_tier=CostTier.PREMIUM,
        max_output_tokens=8192, context_window=256_000, supports_json_mode=True,
    ),
    "gpt-5": ModelSpec(
        provider=ModelProvider.OPENAI, model_id="gpt-5",
        display_name="GPT-5", cost_tier=CostTier.STANDARD,
        max_output_tokens=4096, context_window=128_000, supports_json_mode=True,
    ),
    # ── Google ──
    "gemini-3.1-pro": ModelSpec(
        provider=ModelProvider.GOOGLE, model_id="gemini-3.1-pro",
        display_name="Gemini 3.1 Pro", cost_tier=CostTier.STANDARD,
        max_output_tokens=8192, context_window=1_000_000, supports_json_mode=True,
    ),
    # ── DeepSeek ──
    "deepseek-v4-flash": ModelSpec(
        provider=ModelProvider.DEEPSEEK, model_id="deepseek-v4-flash",
        display_name="DeepSeek V4 Flash", cost_tier=CostTier.BUDGET,
        max_output_tokens=4096, context_window=128_000, supports_json_mode=True,
    ),
    "deepseek-v4": ModelSpec(
        provider=ModelProvider.DEEPSEEK, model_id="deepseek-v4",
        display_name="DeepSeek V4", cost_tier=CostTier.BUDGET,
        max_output_tokens=8192, context_window=128_000, supports_json_mode=True,
    ),
    "deepseek-v4-pro": ModelSpec(
        provider=ModelProvider.DEEPSEEK, model_id="deepseek-v4-pro",
        display_name="DeepSeek V4 Pro", cost_tier=CostTier.STANDARD,
        max_output_tokens=8192, context_window=128_000, supports_json_mode=True,
    ),
    # ── Moonshot ──
    "kimi-k2.6": ModelSpec(
        provider=ModelProvider.MOONSHOT, model_id="kimi-k2.6",
        display_name="Kimi k2.6", cost_tier=CostTier.BUDGET,
        max_output_tokens=4096, context_window=128_000, supports_json_mode=True,
    ),
    # ── Local / Open-Weights ──
    "qwen3-32b": ModelSpec(
        provider=ModelProvider.LOCAL_VLLM, model_id="qwen3-32b",
        display_name="Qwen3-32B (Local)", cost_tier=CostTier.LOCAL,
        max_output_tokens=4096, context_window=32_768,
    ),
}


# ─── Routing Matrix ──────────────────────────────────────────────────────────

@dataclass
class ModelSlot:
    """A single slot in a routing chain."""
    provider: ModelProvider
    model_id: str
    priority: int  # 0 = primary, 1 = first fallback, etc.


# The 2026 default routing matrix. Users override via PlatformSettings.ai_routing_config.
DEFAULT_ROUTING_MATRIX: dict[AITaskType, list[ModelSlot]] = {
    # ── SENTINEL-specific ──
    AITaskType.TRIAGE_COMPRESSION: [
        ModelSlot(ModelProvider.DEEPSEEK, "deepseek-v4-flash", 0),
        ModelSlot(ModelProvider.MOONSHOT, "kimi-k2.6", 1),
        ModelSlot(ModelProvider.OLLAMA, "llama3", 2),
    ],
    AITaskType.EXPLOIT_ANALYSIS: [
        ModelSlot(ModelProvider.ANTHROPIC, "claude-opus-4-20260601", 0),
        ModelSlot(ModelProvider.OPENAI, "gpt-5.5", 1),
        ModelSlot(ModelProvider.GOOGLE, "gemini-3.1-pro", 2),
    ],
    AITaskType.REMEDIATION_GENERATION: [
        ModelSlot(ModelProvider.ANTHROPIC, "claude-opus-4-20260601", 0),
        ModelSlot(ModelProvider.OPENAI, "gpt-5.5", 1),
        ModelSlot(ModelProvider.GOOGLE, "gemini-3.1-pro", 2),
    ],
    # ── General-purpose (user's 2026 matrix) ──
    AITaskType.CODE_REFACTOR: [
        ModelSlot(ModelProvider.ANTHROPIC, "claude-opus-4-20260601", 0),
        ModelSlot(ModelProvider.OPENAI, "gpt-5.5", 1),
    ],
    AITaskType.TERMINAL_AUTOMATION: [
        ModelSlot(ModelProvider.OPENAI, "gpt-5.5", 0),
        ModelSlot(ModelProvider.GOOGLE, "gemini-3.1-pro", 1),
    ],
    AITaskType.DOC_SUMMARIZATION: [
        ModelSlot(ModelProvider.GOOGLE, "gemini-3.1-pro", 0),
        ModelSlot(ModelProvider.ANTHROPIC, "claude-opus-4-20260601", 1),
    ],
    AITaskType.BATCH_CLASSIFICATION: [
        ModelSlot(ModelProvider.DEEPSEEK, "deepseek-v4-flash", 0),
        ModelSlot(ModelProvider.MOONSHOT, "kimi-k2.6", 1),
    ],
    AITaskType.CREATIVE_FRONTEND: [
        ModelSlot(ModelProvider.GOOGLE, "gemini-3.1-pro", 0),
        ModelSlot(ModelProvider.ANTHROPIC, "claude-opus-4-20260601", 1),
    ],
    AITaskType.AIR_GAPPED_EXEC: [
        ModelSlot(ModelProvider.LOCAL_VLLM, "deepseek-v4", 0),
        ModelSlot(ModelProvider.OLLAMA, "qwen3-32b", 1),
    ],
}


# ─── Cost Guardrails ─────────────────────────────────────────────────────────

# Tasks where premium models are wasteful — require force_override=True to proceed.
COST_CEILING_MAP: dict[AITaskType, CostTier] = {
    AITaskType.TRIAGE_COMPRESSION: CostTier.BUDGET,
    AITaskType.BATCH_CLASSIFICATION: CostTier.BUDGET,
}

_TIER_RANK = {CostTier.LOCAL: 0, CostTier.BUDGET: 1, CostTier.STANDARD: 2, CostTier.PREMIUM: 3}


class CostGuardrailViolation(Exception):
    """Raised when a premium model is assigned to a budget task without force_override."""
    def __init__(self, task_type: str, model_id: str, expected_ceiling: str):
        self.task_type = task_type
        self.model_id = model_id
        self.expected_ceiling = expected_ceiling
        super().__init__(
            f"Cost guardrail violation: task '{task_type}' has a '{expected_ceiling}' ceiling, "
            f"but model '{model_id}' exceeds it. Pass force_override=true to proceed."
        )


# ─── Response Schema ─────────────────────────────────────────────────────────

class RoutedResponse(BaseModel):
    """Metadata-rich response from a routed LLM call."""
    content: str = Field(description="Raw LLM output text")
    provider_used: str = Field(description="Provider that served the request")
    model_used: str = Field(description="Model ID that generated the response")
    task_type: str = Field(description="The AITaskType classification")
    latency_ms: float = Field(description="Round-trip call time in milliseconds")
    fallback_chain: list[str] = Field(default_factory=list, description="Providers attempted before success")
    context_injected: bool = Field(default=False, description="Whether session context was auto-injected")
    token_estimate: Optional[int] = Field(default=None, description="Estimated prompt token count")


# ─── The Router ──────────────────────────────────────────────────────────────

class LLMRouter:
    """
    Central intelligence layer that routes AI tasks to optimal models.
    
    Features:
      - Task-specific routing with prioritized fallback chains
      - Contextual auto-injection of session tokens, headers, and scope rules
      - TTLCache (60s) for PlatformSettings to avoid DB bottlenecks
      - Cost guardrails that soft-block premium models on budget tasks
      - Immutable audit trail via AIExecutionLog
    """

    # HTTP timeout for provider calls (seconds)
    _CALL_TIMEOUT = 60.0

    def __init__(self):
        # In-process memory cache for PlatformSettings (60s TTL, 1 slot)
        self._settings_cache: TTLCache = TTLCache(maxsize=1, ttl=60)
        self._cache_key = "platform_settings_default"

    # ── Public API ────────────────────────────────────────────────────────

    async def route(
        self,
        task_type: AITaskType,
        prompt: str,
        system_prompt: str = "",
        override_provider: Optional[ModelProvider] = None,
        override_model: Optional[str] = None,
        inject_context: bool = True,
        force_override: bool = False,
    ) -> RoutedResponse:
        """
        Route a prompt to the optimal model for the given task type.
        
        Args:
            task_type: Classification of the AI task.
            prompt: The user/system prompt to send.
            system_prompt: Optional system-level instructions.
            override_provider: Force a specific provider (bypasses routing matrix).
            override_model: Force a specific model ID.
            inject_context: If True, auto-inject session tokens/headers/scope into system_prompt.
            force_override: If True, bypass cost guardrails.
        
        Returns:
            RoutedResponse with content and full routing metadata.
        
        Raises:
            CostGuardrailViolation: If a premium model is used for a budget task without force_override.
        """
        settings = await self._get_cached_settings()
        
        # Build the routing chain
        chain = self._resolve_routing_chain(task_type, settings, override_provider, override_model)
        
        # Contextual auto-injection
        enriched_system_prompt = system_prompt
        context_was_injected = False
        if inject_context and settings:
            enriched_system_prompt, context_was_injected = await self._inject_context(system_prompt, settings)
        
        # Estimate tokens (rough: 1 token ≈ 4 chars)
        token_estimate = (len(prompt) + len(enriched_system_prompt)) // 4
        
        # Walk the fallback chain
        fallback_trail: list[str] = []
        last_error: Optional[Exception] = None
        
        for slot in chain:
            slot_label = f"{slot.provider.value}:{slot.model_id}"
            
            # Cost guardrail check
            spec = MODEL_CATALOG.get(slot.model_id)
            if spec:
                try:
                    self._check_cost_guardrail(task_type, spec, force_override)
                except CostGuardrailViolation:
                    if slot.priority == 0 and override_model:
                        raise  # User explicitly chose this model — surface the error
                    logger.warning("Cost guardrail skipped slot %s for task %s", slot_label, task_type.value)
                    fallback_trail.append(f"{slot_label} [COST_BLOCKED]")
                    continue
            
            # Resolve API credentials for the provider
            api_key, base_url = self._resolve_credentials(slot.provider, settings)
            
            t0 = time.monotonic()
            try:
                content = await self._dispatch_call(
                    provider=slot.provider,
                    model_id=slot.model_id,
                    prompt=prompt,
                    system_prompt=enriched_system_prompt,
                    api_key=api_key,
                    base_url=base_url,
                )
                latency_ms = (time.monotonic() - t0) * 1000
                
                # Log success
                await self._log_execution(
                    task_type=task_type, provider=slot.provider.value,
                    model=slot.model_id, prompt=prompt, latency_ms=latency_ms,
                    fallback_chain=fallback_trail, success=True,
                    context_injected=context_was_injected,
                    cost_tier=spec.cost_tier.value if spec else None,
                    token_estimate=token_estimate,
                )
                
                return RoutedResponse(
                    content=content,
                    provider_used=slot.provider.value,
                    model_used=slot.model_id,
                    task_type=task_type.value,
                    latency_ms=round(latency_ms, 2),
                    fallback_chain=fallback_trail,
                    context_injected=context_was_injected,
                    token_estimate=token_estimate,
                )
            except Exception as exc:
                latency_ms = (time.monotonic() - t0) * 1000
                last_error = exc
                fallback_trail.append(f"{slot_label} [{type(exc).__name__}]")
                logger.warning(
                    "Provider %s failed for task %s (%.0fms): %s",
                    slot_label, task_type.value, latency_ms, exc,
                )
                continue
        
        # All providers exhausted
        error_msg = f"All providers exhausted for task {task_type.value}. Last error: {last_error}"
        logger.error(error_msg)
        await self._log_execution(
            task_type=task_type, provider="none", model="none",
            prompt=prompt, latency_ms=0, fallback_chain=fallback_trail,
            success=False, error_message=error_msg,
            context_injected=context_was_injected, token_estimate=token_estimate,
        )
        return RoutedResponse(
            content=f"[SENTINEL AI Router] {error_msg}",
            provider_used="none",
            model_used="none",
            task_type=task_type.value,
            latency_ms=0,
            fallback_chain=fallback_trail,
            context_injected=context_was_injected,
            token_estimate=token_estimate,
        )

    async def get_routing_config(self) -> dict:
        """Return the current routing matrix with user overrides applied."""
        settings = await self._get_cached_settings()
        user_overrides = {}
        if settings and settings.ai_routing_config:
            user_overrides = settings.ai_routing_config if isinstance(settings.ai_routing_config, dict) else {}
        
        matrix = {}
        for task_type in AITaskType:
            default_chain = DEFAULT_ROUTING_MATRIX.get(task_type, [])
            override = user_overrides.get(task_type.value)
            matrix[task_type.value] = {
                "default_chain": [
                    {"provider": s.provider.value, "model": s.model_id, "priority": s.priority}
                    for s in default_chain
                ],
                "user_override": override,
                "cost_ceiling": COST_CEILING_MAP.get(task_type, CostTier.PREMIUM).value,
            }
        
        return {
            "routing_matrix": matrix,
            "model_catalog": {
                k: {
                    "provider": v.provider.value,
                    "display_name": v.display_name,
                    "cost_tier": v.cost_tier.value,
                    "context_window": v.context_window,
                    "max_output_tokens": v.max_output_tokens,
                    "supports_json_mode": v.supports_json_mode,
                }
                for k, v in MODEL_CATALOG.items()
            },
            "providers": [p.value for p in ModelProvider],
        }

    async def get_available_providers(self) -> list[dict]:
        """Return which providers have valid credentials configured."""
        settings = await self._get_cached_settings()
        result = []
        for provider in ModelProvider:
            key, url = self._resolve_credentials(provider, settings)
            has_creds = bool(key) or provider in (ModelProvider.OLLAMA, ModelProvider.LOCAL_VLLM)
            result.append({
                "provider": provider.value,
                "configured": has_creds,
                "endpoint": url or "(default)",
            })
        return result

    # ── Settings Cache ────────────────────────────────────────────────────

    async def _get_cached_settings(self):
        """Fetch PlatformSettings with 60s TTL in-process cache."""
        cached = self._settings_cache.get(self._cache_key)
        if cached is not None:
            return cached
        
        try:
            from core.database import AsyncSessionLocal
            from core.models import PlatformSettings
            async with AsyncSessionLocal() as session:
                settings = await session.get(PlatformSettings, "default")
                if settings:
                    self._settings_cache[self._cache_key] = settings
                return settings
        except Exception as e:
            logger.warning("Failed to fetch PlatformSettings: %s", e)
            return None

    def invalidate_cache(self):
        """Force-clear the settings cache (call after settings update)."""
        self._settings_cache.clear()

    # ── Contextual Auto-Injection ─────────────────────────────────────────

    async def _inject_context(self, system_prompt: str, settings) -> tuple[str, bool]:
        """
        Enrich the system prompt with live session context from the database.
        Returns (enriched_prompt, was_injected).
        """
        injections: list[str] = []
        
        # Custom headers
        if settings.custom_headers:
            headers_data = settings.custom_headers
            if isinstance(headers_data, str):
                try:
                    headers_data = json.loads(headers_data)
                except Exception:
                    headers_data = []
            if headers_data:
                header_lines = []
                for h in headers_data:
                    if isinstance(h, dict):
                        header_lines.append(f"  {h.get('key', '')}: {h.get('value', '')}")
                if header_lines:
                    injections.append(
                        "[ACTIVE SESSION HEADERS — inject these into generated curl/HTTP commands]\n"
                        + "\n".join(header_lines)
                    )
        
        # Session cookies
        if settings.session_cookies:
            cookies_data = settings.session_cookies
            if isinstance(cookies_data, str):
                try:
                    cookies_data = json.loads(cookies_data)
                except Exception:
                    cookies_data = []
            if cookies_data:
                cookie_parts = []
                for c in cookies_data:
                    if isinstance(c, dict):
                        cookie_parts.append(f"{c.get('name', '')}={c.get('value', '')}")
                if cookie_parts:
                    injections.append(
                        "[ACTIVE SESSION COOKIES — include in Cookie header of generated payloads]\n"
                        f"  Cookie: {'; '.join(cookie_parts)}"
                    )
        
        # Upstream proxy
        if settings.upstream_proxy:
            injections.append(
                f"[PROXY CONFIGURATION — route generated requests through this proxy]\n"
                f"  Proxy: {settings.upstream_proxy}"
            )
        
        # Scope rules — load from the scope manager
        try:
            from core.scope_manager import scope_manager
            await scope_manager.load_rules()
            if scope_manager._include_rules:
                scope_lines = [f"  INCLUDE: {r['pattern']}" for r in scope_manager._include_rules[:20]]
                injections.append(
                    "[AUTHORIZED SCOPE — ONLY generate payloads targeting these domains/CIDRs]\n"
                    + "\n".join(scope_lines)
                )
            if scope_manager._exclude_rules:
                exclude_lines = [f"  EXCLUDE: {r['pattern']}" for r in scope_manager._exclude_rules[:10]]
                injections.append(
                    "[EXCLUDED TARGETS — NEVER generate payloads for these]\n"
                    + "\n".join(exclude_lines)
                )
        except Exception as e:
            logger.debug("Could not load scope rules for context injection: %s", e)
        
        if not injections:
            return system_prompt, False
        
        context_block = (
            "\n\n═══ SENTINEL LIVE CONTEXT (Auto-Injected) ═══\n"
            + "\n\n".join(injections)
            + "\n═══ END LIVE CONTEXT ═══\n"
        )
        return system_prompt + context_block, True

    # ── Routing Resolution ────────────────────────────────────────────────

    def _resolve_routing_chain(
        self,
        task_type: AITaskType,
        settings,
        override_provider: Optional[ModelProvider],
        override_model: Optional[str],
    ) -> list[ModelSlot]:
        """Build the ordered list of model slots to attempt."""
        # User override (explicit provider+model) takes highest priority
        if override_provider and override_model:
            return [ModelSlot(override_provider, override_model, 0)]
        
        # Check user's per-task routing overrides in PlatformSettings.ai_routing_config
        if settings and settings.ai_routing_config:
            user_cfg = settings.ai_routing_config if isinstance(settings.ai_routing_config, dict) else {}
            task_override = user_cfg.get(task_type.value)
            if task_override and isinstance(task_override, dict):
                provider_str = task_override.get("provider", "")
                model_str = task_override.get("model", "")
                if provider_str and model_str:
                    try:
                        prov = ModelProvider(provider_str)
                        # Prepend user override, then append defaults as fallback
                        chain = [ModelSlot(prov, model_str, 0)]
                        default_chain = DEFAULT_ROUTING_MATRIX.get(task_type, [])
                        for i, slot in enumerate(default_chain):
                            if slot.model_id != model_str:
                                chain.append(ModelSlot(slot.provider, slot.model_id, i + 1))
                        return chain
                    except ValueError:
                        logger.warning("Invalid provider '%s' in routing config", provider_str)
        
        # Default routing matrix
        return list(DEFAULT_ROUTING_MATRIX.get(task_type, [
            ModelSlot(ModelProvider.OLLAMA, "llama3", 0),
        ]))

    def _check_cost_guardrail(
        self, task_type: AITaskType, spec: ModelSpec, force_override: bool
    ) -> None:
        """Raise CostGuardrailViolation if model exceeds the task's cost ceiling."""
        ceiling = COST_CEILING_MAP.get(task_type)
        if ceiling is None:
            return  # No ceiling for this task
        if force_override:
            return  # User explicitly accepted the cost
        if _TIER_RANK.get(spec.cost_tier, 0) > _TIER_RANK.get(ceiling, 0):
            raise CostGuardrailViolation(task_type.value, spec.model_id, ceiling.value)

    # ── Credential Resolution ─────────────────────────────────────────────

    def _resolve_credentials(self, provider: ModelProvider, settings) -> tuple[str, str]:
        """
        Resolve API key and base URL for a provider.
        Returns (api_key, base_url). Either may be empty string.
        """
        if not settings:
            # Fall back to environment variables
            return os.getenv("AI_API_KEY", ""), os.getenv("AI_BASE_URL", "")
        
        if provider == ModelProvider.OPENAI:
            return (settings.openai_key or os.getenv("OPENAI_API_KEY", ""),
                    os.getenv("OPENAI_BASE_URL", ""))
        elif provider == ModelProvider.ANTHROPIC:
            return (settings.anthropic_key or os.getenv("ANTHROPIC_API_KEY", ""),
                    os.getenv("ANTHROPIC_BASE_URL", ""))
        elif provider == ModelProvider.GOOGLE:
            return (settings.google_ai_key or os.getenv("GOOGLE_AI_KEY", ""),
                    os.getenv("GOOGLE_AI_BASE_URL", ""))
        elif provider == ModelProvider.DEEPSEEK:
            return (settings.deepseek_key or os.getenv("DEEPSEEK_API_KEY", ""),
                    os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"))
        elif provider == ModelProvider.OLLAMA:
            return ("", settings.ollama_base_url or os.getenv("OLLAMA_URL", "http://localhost:11434"))
        elif provider == ModelProvider.LOCAL_VLLM:
            return ("", settings.vllm_base_url or os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1"))
        elif provider == ModelProvider.AZURE_AI:
            return (settings.azure_ai_key or os.getenv("AZURE_AI_KEY", ""),
                    settings.azure_ai_endpoint or os.getenv("AZURE_AI_ENDPOINT", ""))
        elif provider == ModelProvider.MOONSHOT:
            return (settings.moonshot_key or os.getenv("MOONSHOT_API_KEY", ""),
                    os.getenv("MOONSHOT_BASE_URL", "https://api.moonshot.cn/v1"))
        return ("", "")

    # ── Provider Dispatch ─────────────────────────────────────────────────

    async def _dispatch_call(
        self,
        provider: ModelProvider,
        model_id: str,
        prompt: str,
        system_prompt: str,
        api_key: str,
        base_url: str,
    ) -> str:
        """Dispatch a prompt to the correct provider backend."""
        dispatch_map = {
            ModelProvider.OPENAI: self._call_openai,
            ModelProvider.ANTHROPIC: self._call_anthropic,
            ModelProvider.GOOGLE: self._call_google,
            ModelProvider.DEEPSEEK: self._call_deepseek,
            ModelProvider.OLLAMA: self._call_ollama,
            ModelProvider.LOCAL_VLLM: self._call_local_vllm,
            ModelProvider.AZURE_AI: self._call_azure_ai,
            ModelProvider.MOONSHOT: self._call_moonshot,
        }
        handler = dispatch_map.get(provider)
        if not handler:
            raise ValueError(f"No handler for provider: {provider}")
        return await handler(prompt, system_prompt, api_key, model_id, base_url)

    async def _call_openai(
        self, prompt: str, system_prompt: str, api_key: str, model: str, base_url: str
    ) -> str:
        url = (base_url.rstrip("/") + "/chat/completions") if base_url else "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=self._CALL_TIMEOUT) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"OpenAI {resp.status_code}: {resp.text[:500]}")
            return resp.json()["choices"][0]["message"]["content"]

    async def _call_anthropic(
        self, prompt: str, system_prompt: str, api_key: str, model: str, base_url: str
    ) -> str:
        url = (base_url.rstrip("/") + "/v1/messages") if base_url else "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2024-10-22",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 8192,
        }
        async with httpx.AsyncClient(timeout=self._CALL_TIMEOUT) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"Anthropic {resp.status_code}: {resp.text[:500]}")
            return resp.json()["content"][0]["text"]

    async def _call_google(
        self, prompt: str, system_prompt: str, api_key: str, model: str, base_url: str
    ) -> str:
        """Google AI (Gemini) via the generativelanguage REST API."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 8192},
        }
        async with httpx.AsyncClient(timeout=self._CALL_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                raise Exception(f"Google AI {resp.status_code}: {resp.text[:500]}")
            candidates = resp.json().get("candidates", [])
            if not candidates:
                raise Exception("Google AI returned no candidates")
            parts = candidates[0].get("content", {}).get("parts", [])
            return parts[0]["text"] if parts else ""

    async def _call_deepseek(
        self, prompt: str, system_prompt: str, api_key: str, model: str, base_url: str
    ) -> str:
        """DeepSeek uses OpenAI-compatible API."""
        url = (base_url.rstrip("/") + "/chat/completions") if base_url else "https://api.deepseek.com/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=self._CALL_TIMEOUT) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"DeepSeek {resp.status_code}: {resp.text[:500]}")
            return resp.json()["choices"][0]["message"]["content"]

    async def _call_ollama(
        self, prompt: str, system_prompt: str, _api_key: str, model: str, base_url: str
    ) -> str:
        url = (base_url.rstrip("/") + "/api/generate")
        payload = {"model": model, "prompt": prompt, "system": system_prompt, "stream": False}
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                raise Exception(f"Ollama {resp.status_code}: {resp.text[:500]}")
            return resp.json().get("response", "")

    async def _call_local_vllm(
        self, prompt: str, system_prompt: str, _api_key: str, model: str, base_url: str
    ) -> str:
        """vLLM uses OpenAI-compatible API (no auth required for local clusters)."""
        url = (base_url.rstrip("/") + "/chat/completions") if base_url else "http://localhost:8000/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                raise Exception(f"vLLM {resp.status_code}: {resp.text[:500]}")
            return resp.json()["choices"][0]["message"]["content"]

    async def _call_azure_ai(
        self, prompt: str, system_prompt: str, api_key: str, model: str, base_url: str
    ) -> str:
        """Azure AI Foundry — OpenAI-compatible with Azure auth headers."""
        if not base_url:
            raise ValueError("Azure AI endpoint is not configured")
        url = f"{base_url.rstrip('/')}/openai/deployments/{model}/chat/completions?api-version=2024-10-21"
        headers = {"api-key": api_key, "Content-Type": "application/json"}
        payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=self._CALL_TIMEOUT) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"Azure AI {resp.status_code}: {resp.text[:500]}")
            return resp.json()["choices"][0]["message"]["content"]

    async def _call_moonshot(
        self, prompt: str, system_prompt: str, api_key: str, model: str, base_url: str
    ) -> str:
        """Moonshot AI (Kimi) uses OpenAI-compatible API."""
        url = (base_url.rstrip("/") + "/chat/completions") if base_url else "https://api.moonshot.cn/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=self._CALL_TIMEOUT) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"Moonshot {resp.status_code}: {resp.text[:500]}")
            return resp.json()["choices"][0]["message"]["content"]

    # ── Audit Logging ─────────────────────────────────────────────────────

    async def _log_execution(
        self,
        task_type: AITaskType,
        provider: str,
        model: str,
        prompt: str,
        latency_ms: float,
        fallback_chain: list[str],
        success: bool,
        error_message: str = None,
        context_injected: bool = False,
        cost_tier: str = None,
        token_estimate: int = None,
    ) -> None:
        """Write an immutable audit log entry."""
        try:
            from core.database import AsyncSessionLocal
            from core.models import AIExecutionLog
            prompt_hash = hashlib.sha256(prompt.encode("utf-8", errors="replace")).hexdigest()
            log_entry = AIExecutionLog(
                task_type=task_type.value,
                provider=provider,
                model=model,
                prompt_hash=prompt_hash,
                latency_ms=round(latency_ms, 2),
                fallback_chain=fallback_chain,
                success=success,
                error_message=error_message,
                context_injected=context_injected,
                cost_tier=cost_tier,
                token_estimate=token_estimate,
            )
            async with AsyncSessionLocal() as session:
                session.add(log_entry)
                await session.commit()
        except Exception as e:
            logger.warning("Failed to write AI execution log: %s", e)


# ─── Global Singleton ─────────────────────────────────────────────────────────

llm_router = LLMRouter()
