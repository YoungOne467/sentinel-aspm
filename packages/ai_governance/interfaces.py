from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class PolicyContext:
    user_id: Optional[str]
    workspace_id: Optional[str]
    tenant_id: Optional[str]
    global_scope: bool = False

@dataclass
class PolicyEvaluation:
    allowed: bool
    reason: str
    policy_name: str

class AIPolicy(ABC):
    @abstractmethod
    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        pass

class RecursionPolicy(AIPolicy):
    """Governs max depth, max tool calls, and max tokens per execution."""
    pass

class LatencyPolicy(AIPolicy):
    """Trips if LLM latency consistently degrades past operational thresholds."""
    pass

class ErrorRatePolicy(AIPolicy):
    """Trips if inference errors exceed safety limits over a time window."""
    pass

class PricingModel(ABC):
    """Abstract interface defining the pricing dimensions for an AI model."""
    @abstractmethod
    def get_input_rate(self) -> float:
        pass
        
    @abstractmethod
    def get_output_rate(self) -> float:
        pass

class CostCalculator(ABC):
    """Calculates granular inference cost based on a specific PricingModel."""
    @abstractmethod
    def calculate_cost(self, pricing: PricingModel, input_tokens: int, output_tokens: int, cached_tokens: int = 0, reasoning_tokens: int = 0) -> float:
        pass

class ProviderPricingRegistry(ABC):
    """Resolves PricingModels dynamically for multi-tenant, multi-tier deployments."""
    @abstractmethod
    def get_pricing(self, provider_id: str, model_id: str) -> PricingModel:
        pass

class CircuitBreaker(ABC):
    @abstractmethod
    def add_policy(self, policy: AIPolicy) -> None:
        pass

    @abstractmethod
    async def evaluate(self, context: PolicyContext, **kwargs) -> PolicyEvaluation:
        pass
        
    @abstractmethod
    async def record(self, context: PolicyContext, *args, **kwargs) -> None:
        pass

    @abstractmethod
    async def trip(self, context: PolicyContext, reason: str) -> None:
        pass

    @abstractmethod
    async def reset(self, context: PolicyContext) -> None:
        pass
