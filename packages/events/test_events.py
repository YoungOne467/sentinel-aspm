"""Tests for the events bounded context: envelope immutability, bus contracts, and Redis serialization."""

import json
import pytest
from dataclasses import FrozenInstanceError
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from packages.events.envelope import EventEnvelope
from packages.events.interfaces import EventBus
from packages.events.redis_bus import RedisStreamEventBus


# ---------------------------------------------------------------------------
# EventEnvelope immutability (frozen dataclass)
# ---------------------------------------------------------------------------

class TestEventEnvelopeImmutability:
    def test_envelope_is_frozen(self):
        """EventEnvelope must be a frozen dataclass — mutation raises FrozenInstanceError."""
        envelope = EventEnvelope(event_type="TestEvent")
        with pytest.raises(FrozenInstanceError):
            envelope.event_type = "Tampered"

    def test_envelope_fields_immutable_after_creation(self):
        """No field on the envelope should be reassignable once constructed."""
        envelope = EventEnvelope(
            event_type="ScanCompleted",
            trace_id="trace-1",
            tenant_id="acme",
            payload={"key": "value"},
        )
        for field_name in ("event_id", "event_type", "trace_id", "correlation_id",
                           "tenant_id", "timestamp", "schema_version",
                           "source_context", "payload"):
            with pytest.raises(FrozenInstanceError):
                setattr(envelope, field_name, "hacked")

    def test_envelope_defaults(self):
        """Defaults populate correctly when no arguments are supplied."""
        envelope = EventEnvelope()
        assert envelope.event_type == "GenericEvent"
        assert envelope.tenant_id == "default"
        assert envelope.schema_version == "1.0"
        assert envelope.source_context == "sentinel"
        assert isinstance(envelope.timestamp, datetime)
        assert isinstance(envelope.payload, dict)
        assert len(envelope.event_id) > 0  # uuid4 string

    def test_envelope_custom_fields(self):
        """Custom values are preserved exactly as supplied."""
        ts = datetime(2026, 1, 1, 12, 0, 0)
        envelope = EventEnvelope(
            event_id="custom-id",
            event_type="CustomEvent",
            trace_id="trace-abc",
            correlation_id="corr-xyz",
            tenant_id="tenant-42",
            timestamp=ts,
            schema_version="2.0",
            source_context="test-suite",
            payload={"severity": "critical"},
        )
        assert envelope.event_id == "custom-id"
        assert envelope.event_type == "CustomEvent"
        assert envelope.trace_id == "trace-abc"
        assert envelope.correlation_id == "corr-xyz"
        assert envelope.tenant_id == "tenant-42"
        assert envelope.timestamp == ts
        assert envelope.schema_version == "2.0"
        assert envelope.source_context == "test-suite"
        assert envelope.payload == {"severity": "critical"}


# ---------------------------------------------------------------------------
# EventBus publish/subscribe contract
# ---------------------------------------------------------------------------

class TestEventBusContract:
    """Verify that EventBus is abstract and enforces the publish/subscribe contract."""

    def test_eventbus_cannot_be_instantiated(self):
        with pytest.raises(TypeError):
            EventBus()

    def test_concrete_implementation_must_implement_publish_and_subscribe(self):
        """A subclass that omits one abstract method should still raise."""

        class IncompleteEventBus(EventBus):
            async def publish(self, topic, envelope):
                pass
            # subscribe intentionally omitted

        with pytest.raises(TypeError):
            IncompleteEventBus()


# ---------------------------------------------------------------------------
# RedisStreamEventBus serialization / deserialization
# ---------------------------------------------------------------------------

class TestRedisStreamEventBusSerialization:
    def setup_method(self):
        self.bus = RedisStreamEventBus.__new__(RedisStreamEventBus)
        self.bus.redis_url = "redis://localhost:6379/0"
        self.bus._client = MagicMock()

    def test_serialize_roundtrip_preserves_all_fields(self):
        """Serialize then deserialize should return an equivalent envelope."""
        original = EventEnvelope(
            event_id="id-123",
            event_type="ScanStarted",
            trace_id="trace-001",
            correlation_id="corr-001",
            tenant_id="acme",
            timestamp=datetime(2026, 6, 1, 10, 30, 0),
            schema_version="1.0",
            source_context="scanner",
            payload={"target": "192.168.1.1"},
        )

        serialized = self.bus._serialize_envelope(original)
        restored = self.bus._deserialize_envelope(serialized)

        assert restored.event_id == original.event_id
        assert restored.event_type == original.event_type
        assert restored.trace_id == original.trace_id
        assert restored.correlation_id == original.correlation_id
        assert restored.tenant_id == original.tenant_id
        assert restored.timestamp == original.timestamp
        assert restored.schema_version == original.schema_version
        assert restored.source_context == original.source_context
        assert restored.payload == original.payload

    def test_serialized_form_is_valid_json(self):
        envelope = EventEnvelope(event_type="TestEvent")
        raw = self.bus._serialize_envelope(envelope)
        data = json.loads(raw)
        assert data["event_type"] == "TestEvent"

    def test_deserialize_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            self.bus._deserialize_envelope("NOT-JSON")


class TestRedisStreamEventBusPublish:
    @pytest.mark.asyncio
    async def test_publish_calls_xadd(self):
        """Publish must write an 'envelope' field to the Redis stream via XADD."""
        bus = RedisStreamEventBus.__new__(RedisStreamEventBus)
        bus.redis_url = "redis://localhost:6379/0"
        bus._client = AsyncMock()

        envelope = EventEnvelope(event_type="AuditEvent", tenant_id="t1")
        await bus.publish("test_topic", envelope)

        bus._client.xadd.assert_awaited_once()
        call_args = bus._client.xadd.call_args
        assert call_args[0][0] == "test_topic"
        assert "envelope" in call_args[0][1]
        # Verify the serialized data is valid JSON
        json.loads(call_args[0][1]["envelope"])
