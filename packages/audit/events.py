from typing import Dict, Any, List
from dataclasses import dataclass
from .interfaces import AuditEvent

@dataclass(frozen=True)
class SecretResolvedEvent(AuditEvent):
    pass

@dataclass(frozen=True)
class SecretResolutionFailedEvent(AuditEvent):
    pass

@dataclass(frozen=True)
class PluginExecutionStartedEvent(AuditEvent):
    pass

@dataclass(frozen=True)
class PluginExecutionCompletedEvent(AuditEvent):
    pass

@dataclass(frozen=True)
class CapabilityDeniedEvent(AuditEvent):
    pass

@dataclass(frozen=True)
class CircuitBreakerOpenedEvent(AuditEvent):
    pass

@dataclass(frozen=True)
class CircuitBreakerClosedEvent(AuditEvent):
    pass
