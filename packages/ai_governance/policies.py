import logging
import json
import time
from typing import Optional, List, Dict, Any
import redis.asyncio as aioredis

from .interfaces import (
    AIPolicy, PolicyContext, PolicyEvaluation, CostCalculator, PricingModel,
    RecursionPolicy, LatencyPolicy, ErrorRatePolicy
)
from packages.observability.slo import (
    policy_evaluations_counter, policy_denials_counter, 
    recursion_stops_counter, tool_call_limit_hits_counter
)

logger = logging.getLogger(__name__)

# Lua script to evaluate and increment token budget atomically
LUA_EVALUATE_TOKEN_BUDGET = """
local key = KEYS[1]
local requested = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])

local current = redis.call('GET', key)
if not current then
    current = 0
end
current = tonumber(current)

if current + requested > limit then
    return 0 -- Denied
else
    redis.call('INCRBY', key, requested)
    return 1 -- Allowed
end
"""

class TokenPolicy(AIPolicy):
    """Enforces atomic tenant-namespaced token consumption using Lua scripts."""
    
    def __init__(self, max_tokens: int, redis_url: str = "redis://localhost:6379/0"):
        self.max_tokens = max_tokens
        self._redis = aioredis.from_url(redis_url, decode_responses=True)

    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "TokenPolicy"})
        requested_tokens = kwargs.get("requested_tokens", 0)
        tenant_id = context.tenant_id or "default"
        key = f"sentinel:tenant:{tenant_id}:tokens"
        
        # Execute Lua script to atomically evaluate and allocate
        try:
            allowed = await self._redis.eval(LUA_EVALUATE_TOKEN_BUDGET, 1, key, requested_tokens, self.max_tokens)
            if allowed == 0:
                policy_denials_counter.add(1, {"policy": "TokenPolicy", "tenant_id": tenant_id})
                return PolicyEvaluation(
                    allowed=False,
                    reason=f"Tenant token budget exceeded. Requested: {requested_tokens}, Limit: {self.max_tokens}",
                    policy_name="TokenPolicy"
                )
            return PolicyEvaluation(allowed=True, reason="Token budget available", policy_name="TokenPolicy")
        except Exception as e:
            logger.error(f"Redis TokenPolicy evaluation failed: {e}")
            return PolicyEvaluation(allowed=True, reason="Redis offline - bypassed for resilience", policy_name="TokenPolicy")

    async def record(self, context: PolicyContext, **kwargs) -> None:
        # Increment is already performed atomically inside the Lua evaluate step to prevent races.
        pass


class CostPolicy(AIPolicy):
    """Enforces atomic tenant-namespaced cost limits using Lua scripts."""
    
    def __init__(self, max_cost_usd: float, cost_calculator: CostCalculator, pricing_model: PricingModel, redis_url: str = "redis://localhost:6379/0"):
        self.max_cost = max_cost_usd
        self.calculator = cost_calculator
        self.pricing = pricing_model
        self._redis = aioredis.from_url(redis_url, decode_responses=True)

    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "CostPolicy"})
        requested_tokens = kwargs.get("requested_tokens", 0)
        tenant_id = context.tenant_id or "default"
        key = f"sentinel:tenant:{tenant_id}:cost"
        
        # Calculate cost in float and convert to micro-dollars to store as integer in Redis
        estimated_cost = self.calculator.calculate_cost(self.pricing, input_tokens=0, output_tokens=requested_tokens)
        cost_micro = int(estimated_cost * 1_000_000)
        limit_micro = int(self.max_cost * 1_000_000)
        
        try:
            allowed = await self._redis.eval(LUA_EVALUATE_TOKEN_BUDGET, 1, key, cost_micro, limit_micro)
            if allowed == 0:
                policy_denials_counter.add(1, {"policy": "CostPolicy", "tenant_id": tenant_id})
                return PolicyEvaluation(
                    allowed=False,
                    reason=f"Tenant cost budget exceeded. Estimated: ${estimated_cost:.4f}, Limit: ${self.max_cost:.2f}",
                    policy_name="CostPolicy"
                )
            return PolicyEvaluation(allowed=True, reason="Cost budget available", policy_name="CostPolicy")
        except Exception as e:
            logger.error(f"Redis CostPolicy evaluation failed: {e}")
            return PolicyEvaluation(allowed=True, reason="Redis offline - bypassed for resilience", policy_name="CostPolicy")

    async def record(self, context: PolicyContext, **kwargs) -> None:
        pass


class BudgetHierarchyPolicy(AIPolicy):
    """Evaluates budget precedence rules: Global Tenant -> Workspace -> Model Class -> Request."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self._redis = aioredis.from_url(redis_url, decode_responses=True)

    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "BudgetHierarchyPolicy"})
        tenant_id = context.tenant_id or "default"
        workspace_id = context.workspace_id or "default"
        model_class = kwargs.get("model_class", "standard") # "premium" | "standard" | "local"
        requested_tokens = kwargs.get("requested_tokens", 0)

        # Build list of Redis keys to check precedence
        # 1. Global Tenant Limit (e.g. max 5,000,000 tokens)
        # 2. Workspace Limit (e.g. max 500,000 tokens)
        # 3. Model Class Limit (e.g. Premium restricted to 100,000)
        keys = [
            (f"sentinel:tenant:{tenant_id}:budget:limit", 5000000, "Global Tenant"),
            (f"sentinel:tenant:{tenant_id}:workspace:{workspace_id}:budget:limit", 500000, "Workspace"),
            (f"sentinel:tenant:{tenant_id}:model:{model_class}:budget:limit", 100000, f"Model Class ({model_class})")
        ]

        for redis_limit_key, default_limit, name in keys:
            try:
                # Query limits
                limit_str = await self._redis.get(redis_limit_key)
                limit = int(limit_str) if limit_str else default_limit
                
                # Check current usage
                usage_key = redis_limit_key.replace(":limit", ":usage")
                usage_str = await self._redis.get(usage_key)
                usage = int(usage_str) if usage_str else 0
                
                if usage + requested_tokens > limit:
                    policy_denials_counter.add(1, {"policy": "BudgetHierarchyPolicy", "tenant_id": tenant_id})
                    return PolicyEvaluation(
                        allowed=False,
                        reason=f"Hierarchy Budget violation: {name} limit reached ({usage + requested_tokens} > {limit})",
                        policy_name="BudgetHierarchyPolicy"
                    )
            except Exception as e:
                logger.error(f"BudgetHierarchyPolicy failed to fetch Redis key: {e}")
                
        return PolicyEvaluation(allowed=True, reason="All hierarchical budgets satisfied", policy_name="BudgetHierarchyPolicy")

    async def record(self, context: PolicyContext, **kwargs) -> None:
        tenant_id = context.tenant_id or "default"
        workspace_id = context.workspace_id or "default"
        model_class = kwargs.get("model_class", "standard")
        tokens = kwargs.get("tokens", 0)
        
        # Atomically increment usage keys in background
        keys = [
            f"sentinel:tenant:{tenant_id}:budget:usage",
            f"sentinel:tenant:{tenant_id}:workspace:{workspace_id}:budget:usage",
            f"sentinel:tenant:{tenant_id}:model:{model_class}:budget:usage"
        ]
        try:
            for k in keys:
                await self._redis.incrby(k, tokens)
        except Exception as e:
            logger.error(f"BudgetHierarchyPolicy record failed: {e}")


class ProviderQuotaPolicy(AIPolicy):
    """Enforces absolute query rate/quota quotas per AI provider."""
    
    def __init__(self, max_requests_per_min: int = 60, redis_url: str = "redis://localhost:6379/0"):
        self.max_requests = max_requests_per_min
        self._redis = aioredis.from_url(redis_url, decode_responses=True)

    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "ProviderQuotaPolicy"})
        provider = kwargs.get("provider", "local")
        tenant_id = context.tenant_id or "default"
        
        # Minute window key
        current_minute = int(time.time() / 60)
        key = f"sentinel:tenant:{tenant_id}:provider:{provider}:quota:{current_minute}"
        
        try:
            current = await self._redis.get(key)
            usage = int(current) if current else 0
            
            if usage >= self.max_requests:
                policy_denials_counter.add(1, {"policy": "ProviderQuotaPolicy", "tenant_id": tenant_id})
                return PolicyEvaluation(
                    allowed=False,
                    reason=f"Provider quota hit. Maximum rate limit is {self.max_requests} req/min.",
                    policy_name="ProviderQuotaPolicy"
                )
            
            # Increment and set TTL
            async with self._redis.pipeline() as pipe:
                pipe.incr(key)
                pipe.expire(key, 65)
                await pipe.execute()
                
            return PolicyEvaluation(allowed=True, reason="Within provider quota", policy_name="ProviderQuotaPolicy")
        except Exception as e:
            logger.error(f"ProviderQuotaPolicy failed: {e}")
            return PolicyEvaluation(allowed=True, reason="Bypassed - Redis offline", policy_name="ProviderQuotaPolicy")


class ConcurrencyPolicy(AIPolicy):
    """Limits concurrent executing requests per tenant using a Redis counter."""
    
    def __init__(self, max_concurrency: int = 5, redis_url: str = "redis://localhost:6379/0"):
        self.max_concurrency = max_concurrency
        self._redis = aioredis.from_url(redis_url, decode_responses=True)

    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "ConcurrencyPolicy"})
        tenant_id = context.tenant_id or "default"
        key = f"sentinel:tenant:{tenant_id}:concurrency"
        
        try:
            current = await self._redis.get(key)
            usage = int(current) if current else 0
            
            if usage >= self.max_concurrency:
                policy_denials_counter.add(1, {"policy": "ConcurrencyPolicy", "tenant_id": tenant_id})
                return PolicyEvaluation(
                    allowed=False,
                    reason=f"Concurrency limit exceeded ({usage} >= {self.max_concurrency})",
                    policy_name="ConcurrencyPolicy"
                )
            return PolicyEvaluation(allowed=True, reason="Concurrency slot available", policy_name="ConcurrencyPolicy")
        except Exception as e:
            logger.error(f"ConcurrencyPolicy failed: {e}")
            return PolicyEvaluation(allowed=True, reason="Bypassed - Redis offline", policy_name="ConcurrencyPolicy")

    async def record(self, context: PolicyContext, **kwargs) -> None:
        # Track when active runs begin or end
        tenant_id = context.tenant_id or "default"
        key = f"sentinel:tenant:{tenant_id}:concurrency"
        action = kwargs.get("action") # "acquire" | "release"
        
        try:
            if action == "acquire":
                await self._redis.incr(key)
            elif action == "release":
                await self._redis.decr(key)
        except Exception as e:
            logger.error(f"ConcurrencyPolicy tracking failed: {e}")


class DefaultRecursionPolicy(RecursionPolicy):
    def __init__(self, max_depth: int = 8):
        self.max_depth = max_depth
        
    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "RecursionPolicy"})
        current_depth = kwargs.get("current_depth", 0)
        if current_depth > self.max_depth:
            recursion_stops_counter.add(1, {"tenant_id": context.tenant_id or "default"})
            return PolicyEvaluation(
                allowed=False,
                reason=f"Recursion depth limit exceeded: {current_depth} > {self.max_depth}",
                policy_name="RecursionPolicy"
            )
        return PolicyEvaluation(allowed=True, reason="Within limit", policy_name="RecursionPolicy")


class ToolCallPolicy(AIPolicy):
    def __init__(self, max_tool_calls: int = 20):
        self.max_tool_calls = max_tool_calls
        
    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "ToolCallPolicy"})
        tool_calls = kwargs.get("tool_calls_count", 0)
        if tool_calls > self.max_tool_calls:
            tool_call_limit_hits_counter.add(1, {"tenant_id": context.tenant_id or "default"})
            return PolicyEvaluation(
                allowed=False,
                reason=f"Tool call limit exceeded: {tool_calls} > {self.max_tool_calls}",
                policy_name="ToolCallPolicy"
            )
        return PolicyEvaluation(allowed=True, reason="Within limit", policy_name="ToolCallPolicy")


class ExecutionDepthPolicy(AIPolicy):
    def __init__(self, max_depth: int = 8):
        self.max_depth = max_depth
        
    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "ExecutionDepthPolicy"})
        spawn_depth = kwargs.get("spawn_depth", 0)
        if spawn_depth > self.max_depth:
            return PolicyEvaluation(
                allowed=False,
                reason=f"Execution spawn depth exceeded: {spawn_depth} > {self.max_depth}",
                policy_name="ExecutionDepthPolicy"
            )
        return PolicyEvaluation(allowed=True, reason="Within limit", policy_name="ExecutionDepthPolicy")


class DefaultLatencyPolicy(LatencyPolicy):
    def __init__(self, max_latency_ms: float = 10000.0):
        self.max_latency_ms = max_latency_ms
        self._latencies: List[float] = []
        
    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "LatencyPolicy"})
        if len(self._latencies) >= 5:
            avg_latency = sum(self._latencies[-5:]) / 5.0
            if avg_latency > self.max_latency_ms:
                return PolicyEvaluation(
                    allowed=False,
                    reason=f"Operational latency degradation detected: avg latency is {avg_latency:.1f}ms (threshold: {self.max_latency_ms}ms)",
                    policy_name="LatencyPolicy"
                )
        return PolicyEvaluation(allowed=True, reason="Operational latency within limits", policy_name="LatencyPolicy")

    async def record(self, context: PolicyContext, **kwargs) -> None:
        latency = kwargs.get("latency_ms")
        if latency is not None:
            self._latencies.append(latency)


class DefaultErrorRatePolicy(ErrorRatePolicy):
    def __init__(self, max_error_rate: float = 0.5, window_size: int = 10):
        self.max_error_rate = max_error_rate
        self.window_size = window_size
        self._history: List[bool] = []
        
    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        policy_evaluations_counter.add(1, {"policy": "ErrorRatePolicy"})
        if len(self._history) >= self.window_size:
            errors = self._history[-self.window_size:].count(False)
            rate = errors / self.window_size
            if rate > self.max_error_rate:
                return PolicyEvaluation(
                    allowed=False,
                    reason=f"Error rate safety threshold exceeded: {rate:.1%} failures in last {self.window_size} cycles",
                    policy_name="ErrorRatePolicy"
                )
        return PolicyEvaluation(allowed=True, reason="Error rate within safe range", policy_name="ErrorRatePolicy")

    async def record(self, context: PolicyContext, **kwargs) -> None:
        success = kwargs.get("success")
        if success is not None:
            self._history.append(success)


# Concrete pricing model and cost calculator implementations
class SimplePricingModel(PricingModel):
    def get_input_rate(self) -> float: return 0.01 / 1000
    def get_output_rate(self) -> float: return 0.02 / 1000

class SimpleCostCalculator(CostCalculator):
    def calculate_cost(self, pricing: PricingModel, input_tokens: int, output_tokens: int, cached_tokens: int = 0, reasoning_tokens: int = 0) -> float:
        return (input_tokens * pricing.get_input_rate()) + (output_tokens * pricing.get_output_rate())
