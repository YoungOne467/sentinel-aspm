import logging
from typing import List
from packages.audit.emitter import audit_emitter
from packages.audit.events import CircuitBreakerOpenedEvent, CircuitBreakerClosedEvent
from .interfaces import CircuitBreaker, AIPolicy, PolicyContext, PolicyEvaluation
# Imports from policies are handled globally where instantiated.

logger = logging.getLogger(__name__)

class DefaultCircuitBreaker(CircuitBreaker):
    def __init__(self):
        self._policies: List[AIPolicy] = []
        self._is_tripped = False
        self._trip_reason = ""
        
    def add_policy(self, policy: AIPolicy) -> None:
        self._policies.append(policy)

    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        if self._is_tripped:
            return PolicyEvaluation(
                allowed=False, 
                reason=f"Circuit Breaker is open. Trip reason: {self._trip_reason}", 
                policy_name="CircuitBreaker"
            )
            
        for policy in self._policies:
            eval_result = await policy.evaluate(context, **kwargs)
            if not eval_result.allowed:
                # Trip the breaker
                await self.trip(context, f"Tripped by {eval_result.policy_name}: {eval_result.reason}")
                return eval_result
                
        return PolicyEvaluation(allowed=True, reason="All policies passed", policy_name="CircuitBreaker")

    async def record(self, context: PolicyContext, *args, **kwargs) -> None:
        if self._is_tripped:
            return
            
        for policy in self._policies:
            if hasattr(policy, "record"):
                await policy.record(context, *args, **kwargs)

    async def trip(self, context: PolicyContext, reason: str) -> None:
        if not self._is_tripped:
            self._is_tripped = True
            self._trip_reason = reason
            await audit_emitter.emit(
                CircuitBreakerOpenedEvent(
                    name="CircuitBreakerOpened",
                    payload={"policy_name": "Unknown", "reason": reason}
                ),
                actor=context.user_id or "system"
            )
            logger.warning(f"CircuitBreaker Tripped: {reason}")

    async def reset(self, context: PolicyContext) -> None:
        if self._is_tripped:
            self._is_tripped = False
            self._trip_reason = ""
            await audit_emitter.emit(
                CircuitBreakerClosedEvent(
                    name="CircuitBreakerClosed",
                    payload={"policy_name": "Unknown"}
                ),
                actor=context.user_id or "system"
            )
            logger.info("CircuitBreaker Reset")

# Global singleton for now
circuit_breaker = DefaultCircuitBreaker()

from .policies import (
    TokenPolicy, CostPolicy, SimplePricingModel, SimpleCostCalculator,
    DefaultRecursionPolicy, ToolCallPolicy, ExecutionDepthPolicy,
    DefaultLatencyPolicy, DefaultErrorRatePolicy,
    BudgetHierarchyPolicy, ProviderQuotaPolicy, ConcurrencyPolicy
)

# Consumption Governance
circuit_breaker.add_policy(TokenPolicy(max_tokens=1000000))
circuit_breaker.add_policy(CostPolicy(max_cost_usd=100.0, cost_calculator=SimpleCostCalculator(), pricing_model=SimplePricingModel()))
circuit_breaker.add_policy(BudgetHierarchyPolicy())

# Behavioral Governance
circuit_breaker.add_policy(DefaultRecursionPolicy(max_depth=8))
circuit_breaker.add_policy(ToolCallPolicy(max_tool_calls=20))
circuit_breaker.add_policy(ExecutionDepthPolicy(max_depth=8))

# Reliability Governance
circuit_breaker.add_policy(DefaultLatencyPolicy(max_latency_ms=10000.0))
circuit_breaker.add_policy(DefaultErrorRatePolicy(max_error_rate=0.5, window_size=10))
circuit_breaker.add_policy(ProviderQuotaPolicy(max_requests_per_min=60))
circuit_breaker.add_policy(ConcurrencyPolicy(max_concurrency=5))
