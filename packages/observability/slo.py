import time
import logging
from typing import Dict
from opentelemetry import metrics

logger = logging.getLogger(__name__)

# Initialize OTel Meter
meter = metrics.get_meter("sentinel_slo")

# Histograms tracking p95 target SLOs
api_latency_hist = meter.create_histogram(
    name="sentinel_api_latency_seconds",
    description="SLO Target: p95 latency < 500ms",
    unit="s"
)

gov_eval_hist = meter.create_histogram(
    name="sentinel_governance_eval_seconds",
    description="SLO Target: p95 evaluation < 50ms",
    unit="s"
)

audit_publish_hist = meter.create_histogram(
    name="sentinel_audit_publish_seconds",
    description="SLO Target: p95 event publication < 100ms",
    unit="s"
)

execution_startup_hist = meter.create_histogram(
    name="sentinel_execution_startup_seconds",
    description="SLO Target: p95 sandbox startup < 5s",
    unit="s"
)

llm_routing_hist = meter.create_histogram(
    name="sentinel_llm_routing_seconds",
    description="SLO Target: p95 routing decision < 100ms",
    unit="s"
)

# Counter Metrics for Governance control plane
policy_evaluations_counter = meter.create_counter(
    name="sentinel_policy_evaluations_total",
    description="Total count of governance policy evaluations"
)

policy_denials_counter = meter.create_counter(
    name="sentinel_policy_denials_total",
    description="Total count of policy denials"
)

provider_fallbacks_counter = meter.create_counter(
    name="sentinel_provider_fallbacks_total",
    description="Total count of provider failures and fallback actions"
)

recursion_stops_counter = meter.create_counter(
    name="sentinel_recursion_stops_total",
    description="Total count of recursion loops blocked by safety policy"
)

tool_call_limit_hits_counter = meter.create_counter(
    name="sentinel_tool_call_limit_hits_total",
    description="Total count of tool call limits reached"
)

class SLOMonitor:
    """Utility class to measure execution durations and publish to SLO metrics."""
    
    def __init__(self, metric_histogram, attributes: Dict[str, str] = None):
        self.metric = metric_histogram
        self.attributes = attributes or {}
        self.start_time = 0.0

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.perf_counter() - self.start_time
        self.metric.record(duration, self.attributes)
        duration_ms = duration * 1000.0
        metric_name = getattr(self.metric, "name", "unknown")
        logger.debug(f"SLO metric recorded: {metric_name} = {duration_ms:.2f}ms")
