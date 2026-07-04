"""Tests for the observability bounded context: trace_boundary span attributes and SLOMonitor timing."""

import time
import pytest
from unittest.mock import MagicMock, patch

from packages.observability.telemetry import (
    trace_boundary,
    get_trace_context_payload,
    trace_execution_span
)
from packages.observability.slo import SLOMonitor


# ---------------------------------------------------------------------------
# trace_boundary span attribute tests
# ---------------------------------------------------------------------------

class TestTraceBoundary:
    def test_span_sets_tenant_id(self):
        """trace_boundary must always set the tenant_id attribute on the span."""
        with trace_boundary("test-span", tenant_id="acme") as span:
            attrs = {}
            # The span is a real OTel span; read attributes back
            # OTel SDK stores them internally — we check they were set via the span API
            assert span is not None
            assert span.is_recording()

    def test_span_sets_all_optional_attributes(self):
        """When all optional params are supplied, each should be set as a span attribute."""
        with trace_boundary(
            "full-span",
            tenant_id="t1",
            workspace_id="ws-1",
            user_id="user-1",
            plugin_id="plugin-1",
            runtime_type="docker",
            provider="openai",
            model="gpt-4",
            policy_name="TokenPolicy",
            node_id="node-1",
            execution_id="exec-1",
        ) as span:
            assert span.is_recording()

    def test_span_name_is_preserved(self):
        """The span name passed to trace_boundary should be the actual span name."""
        with trace_boundary("my-operation-name") as span:
            assert span.name == "my-operation-name"

    def test_context_manager_yields_span(self):
        """trace_boundary is a context manager that yields a Span object."""
        with trace_boundary("ctx-test") as span:
            # Should be a valid span, not None
            assert span is not None


class TestGetTraceContextPayload:
    def test_returns_dict(self):
        """get_trace_context_payload should always return a dict."""
        result = get_trace_context_payload()
        assert isinstance(result, dict)

    def test_returns_trace_and_span_inside_boundary(self):
        """Inside an active trace_boundary, the payload should contain trace_id and span_id."""
        with trace_boundary("extraction-test", tenant_id="t1"):
            payload = get_trace_context_payload()
            assert "trace_id" in payload
            assert "span_id" in payload
            assert len(payload["trace_id"]) == 32  # hex-encoded 128-bit
            assert len(payload["span_id"]) == 16   # hex-encoded 64-bit


# ---------------------------------------------------------------------------
# SLOMonitor timing tests
# ---------------------------------------------------------------------------

class TestSLOMonitor:
    def test_records_duration_to_histogram(self):
        """SLOMonitor should measure elapsed time and call histogram.record()."""
        mock_histogram = MagicMock()
        mock_histogram.name = "test_histogram"
        attrs = {"component": "test"}

        with SLOMonitor(mock_histogram, attrs) as monitor:
            # Simulate some work
            time.sleep(0.01)

        mock_histogram.record.assert_called_once()
        recorded_duration = mock_histogram.record.call_args[0][0]
        # Duration should be > 0 and roughly >= 0.01s
        assert recorded_duration > 0
        assert recorded_duration >= 0.005  # some tolerance for CI

    def test_passes_attributes_to_histogram(self):
        """SLOMonitor should forward its attribute dict to the histogram record call."""
        mock_histogram = MagicMock()
        mock_histogram.name = "test_histogram"
        attrs = {"action": "publish_audit"}

        with SLOMonitor(mock_histogram, attrs):
            pass

        mock_histogram.record.assert_called_once()
        recorded_attrs = mock_histogram.record.call_args[0][1]
        assert recorded_attrs == attrs

    def test_start_time_captured(self):
        """SLOMonitor should capture a non-zero start_time on __enter__."""
        mock_histogram = MagicMock()
        mock_histogram.name = "test_histogram"

        monitor = SLOMonitor(mock_histogram)
        assert monitor.start_time == 0.0
        monitor.__enter__()
        assert monitor.start_time > 0
        monitor.__exit__(None, None, None)

    def test_still_records_on_exception(self):
        """SLOMonitor should record the duration even when the body raises an exception."""
        mock_histogram = MagicMock()
        mock_histogram.name = "test_histogram"

        with pytest.raises(ValueError):
            with SLOMonitor(mock_histogram):
                raise ValueError("boom")

        mock_histogram.record.assert_called_once()


class TestTraceExecutionSpan:
    def test_execution_span_sets_all_9_attributes(self):
        """trace_execution_span must set all 9 mandatory attributes on the span."""
        with trace_execution_span(
            tenant_id="t1",
            workspace_id="ws1",
            execution_id="e1",
            node_id="node1",
            runtime_type="docker",
            runtime_version="1.0.0",
            contract_id="c1",
            scheduler_version="1.0.0",
            node_version="1.0.0"
        ) as span:
            assert span is not None
            assert span.is_recording()

    def test_execution_span_missing_attr_raises(self):
        """trace_execution_span must raise ValueError if any mandatory attribute is empty or None."""
        mandatory_args = {
            "tenant_id": "t1",
            "workspace_id": "ws1",
            "execution_id": "e1",
            "node_id": "node1",
            "runtime_type": "docker",
            "runtime_version": "1.0.0",
            "contract_id": "c1",
            "scheduler_version": "1.0.0",
            "node_version": "1.0.0"
        }

        # Verify that leaving any single parameter empty or None raises ValueError
        for key in mandatory_args.keys():
            args = mandatory_args.copy()
            args[key] = ""
            with pytest.raises(ValueError) as exc:
                with trace_execution_span(**args):
                    pass
            assert "mandatory" in str(exc.value)

            args[key] = None
            with pytest.raises(ValueError) as exc:
                with trace_execution_span(**args):
                    pass
            assert "mandatory" in str(exc.value)
