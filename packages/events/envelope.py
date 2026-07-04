from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any
import uuid

@dataclass(frozen=True)
class EventEnvelope:
    """Canonical event envelope ensuring immutable, trace-correlated, and schema-versioned event payloads."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "GenericEvent"
    trace_id: str = ""
    correlation_id: str = ""
    tenant_id: str = "default"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    schema_version: str = "1.0"
    source_context: str = "sentinel"
    payload: Dict[str, Any] = field(default_factory=dict)
