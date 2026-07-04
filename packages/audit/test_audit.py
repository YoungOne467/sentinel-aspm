"""Tests for the audit bounded context: EventBusAuditEmitter and audit event envelope structure."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import FrozenInstanceError

from packages.audit.interfaces import AuditEvent
from packages.audit.events import (
    SecretResolvedEvent,
    SecretResolutionFailedEvent,
    PluginExecutionStartedEvent,
    PluginExecutionCompletedEvent,
    CapabilityDeniedEvent,
    CircuitBreakerOpenedEvent,
    CircuitBreakerClosedEvent,
)
from packages.events.envelope import EventEnvelope


# ---------------------------------------------------------------------------
# Audit event structure tests (frozen dataclasses)
# ---------------------------------------------------------------------------

class TestAuditEventStructure:
    def test_audit_event_is_frozen(self):
        """AuditEvent subclasses must be frozen (immutable)."""
        event = SecretResolvedEvent(name="SecretResolved", payload={"key": "test"})
        with pytest.raises(FrozenInstanceError):
            event.name = "Tampered"

    def test_all_event_types_are_frozen(self):
        """Every concrete audit event type should be a frozen dataclass."""
        event_classes = [
            SecretResolvedEvent,
            SecretResolutionFailedEvent,
            PluginExecutionStartedEvent,
            PluginExecutionCompletedEvent,
            CapabilityDeniedEvent,
            CircuitBreakerOpenedEvent,
            CircuitBreakerClosedEvent,
        ]
        for cls in event_classes:
            event = cls(name="Test", payload={"x": 1})
            with pytest.raises(FrozenInstanceError):
                event.name = "Hacked"

    def test_audit_event_has_name_and_payload(self):
        """Each audit event must carry a name and payload dict."""
        event = PluginExecutionStartedEvent(
            name="PluginExecutionStarted",
            payload={"plugin_id": "nmap", "capabilities": ["network:external"]},
        )
        assert event.name == "PluginExecutionStarted"
        assert event.payload["plugin_id"] == "nmap"

    def test_all_events_are_audit_event_subclasses(self):
        """All concrete events must be subclasses of AuditEvent."""
        event_classes = [
            SecretResolvedEvent,
            SecretResolutionFailedEvent,
            PluginExecutionStartedEvent,
            PluginExecutionCompletedEvent,
            CapabilityDeniedEvent,
            CircuitBreakerOpenedEvent,
            CircuitBreakerClosedEvent,
        ]
        for cls in event_classes:
            assert issubclass(cls, AuditEvent)


# ---------------------------------------------------------------------------
# EventBusAuditEmitter publishes to event bus
# ---------------------------------------------------------------------------

class TestEventBusAuditEmitter:
    @pytest.mark.asyncio
    @patch("packages.audit.emitter.event_bus")
    async def test_emit_publishes_to_audit_topic(self, mock_bus):
        """EventBusAuditEmitter.emit() should call event_bus.publish() with the audit topic."""
        mock_bus.publish = AsyncMock()

        from packages.audit.emitter import EventBusAuditEmitter

        emitter = EventBusAuditEmitter()
        event = SecretResolvedEvent(
            name="SecretResolved",
            payload={"key": "API_KEY", "provider": "EnvironmentSecretProvider", "success": True},
        )

        await emitter.emit(event, actor="test-user")

        mock_bus.publish.assert_awaited_once()
        call_args = mock_bus.publish.call_args
        assert call_args[0][0] == "sentinel_audit_logs"

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.event_bus")
    async def test_emit_creates_valid_envelope(self, mock_bus):
        """The emitted envelope should contain the event name, actor, and event data."""
        mock_bus.publish = AsyncMock()

        from packages.audit.emitter import EventBusAuditEmitter

        emitter = EventBusAuditEmitter()
        event = CapabilityDeniedEvent(
            name="CapabilityDenied",
            payload={"plugin_id": "evil-plugin", "reason": "untrusted"},
        )

        await emitter.emit(event, actor="admin")

        envelope = mock_bus.publish.call_args[0][1]
        assert isinstance(envelope, EventEnvelope)
        assert envelope.event_type == "CapabilityDenied"
        assert envelope.source_context == "sentinel-audit"
        assert envelope.schema_version == "1.0"
        assert envelope.payload["actor"] == "admin"
        assert envelope.payload["event_data"]["plugin_id"] == "evil-plugin"

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.event_bus")
    async def test_emit_survives_bus_failure(self, mock_bus):
        """If the event bus publish fails, emit should not propagate the exception."""
        mock_bus.publish = AsyncMock(side_effect=Exception("Redis down"))

        from packages.audit.emitter import EventBusAuditEmitter

        emitter = EventBusAuditEmitter()
        event = CircuitBreakerOpenedEvent(
            name="CircuitBreakerOpened",
            payload={"policy_name": "TokenPolicy", "reason": "budget exceeded"},
        )

        # Should not raise
        await emitter.emit(event, actor="system")

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.event_bus")
    async def test_emit_includes_trace_correlation(self, mock_bus):
        """The envelope should carry trace_id for cross-context correlation."""
        mock_bus.publish = AsyncMock()

        from packages.audit.emitter import EventBusAuditEmitter

        emitter = EventBusAuditEmitter()
        event = SecretResolutionFailedEvent(
            name="SecretResolutionFailed",
            payload={"key": "MISSING_KEY"},
        )

        await emitter.emit(event, actor="scanner")

        envelope = mock_bus.publish.call_args[0][1]
        # trace_id should be a string (possibly empty if no active span)
        assert isinstance(envelope.trace_id, str)
        # correlation_id should also be set
        assert isinstance(envelope.correlation_id, str)

    @pytest.mark.asyncio
    @patch("packages.audit.emitter.event_bus")
    async def test_emit_uses_tenant_from_payload(self, mock_bus):
        """If tenant_id is present in the event payload, it should be used in the envelope."""
        mock_bus.publish = AsyncMock()

        from packages.audit.emitter import EventBusAuditEmitter

        emitter = EventBusAuditEmitter()
        event = PluginExecutionCompletedEvent(
            name="PluginExecutionCompleted",
            payload={"plugin_id": "nmap", "exit_code": 0, "tenant_id": "acme-corp"},
        )

        await emitter.emit(event, actor="scheduler")

        envelope = mock_bus.publish.call_args[0][1]
        assert envelope.tenant_id == "acme-corp"
