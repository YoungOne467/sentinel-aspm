from abc import ABC
from typing import Dict, Any
from dataclasses import dataclass

@dataclass(frozen=True)
class AuditEvent(ABC):
    """Base class for all structured, immutable audit events."""
    name: str
    payload: Dict[str, Any]

class AuditEmitter(ABC):
    """Emits immutable audit events for security-sensitive actions."""
    
    async def emit(self, event: AuditEvent, actor: str) -> None:
        """
        Standard Event Types:
        - SecretResolved
        - SecretResolutionFailed
        - PluginExecutionStarted
        - PluginExecutionCompleted
        - CapabilityDenied
        - CircuitBreakerOpened
        - CircuitBreakerClosed
        """
        pass
