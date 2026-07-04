from typing import Dict, Any
from packages.execution.fleet import FleetRegistry

class FleetMetricsCollector:
    """
    Read-only view of the FleetRegistry exposing operational metrics.
    Metrics are traceable to tenant and runtime classes.
    """

    def __init__(self, registry: FleetRegistry):
        self._registry = registry

    def get_node_counts_by_state(self) -> Dict[str, int]:
        counts = {
            "healthy": 0,
            "degraded": 0,
            "draining": 0,
            "offline": 0,
            "quarantined": 0
        }
        for node in self._registry._nodes.values():
            status = node.health_status
            if status in counts:
                counts[status] += 1
        return counts

    def get_resource_utilization(self) -> Dict[str, Any]:
        total_mem = 0
        alloc_mem = 0
        total_cpu = 0.0
        alloc_cpu = 0.0
        
        # Breakdown by tenant and runtime class
        by_tenant = {}
        by_runtime = {}

        for node in self._registry._nodes.values():
            total_mem += node.total_memory
            alloc_mem += node.allocated_memory
            total_cpu += node.total_cpu
            alloc_cpu += node.allocated_cpu
            
            # Tenant breakdown
            t = node.tenant_scope
            if t not in by_tenant:
                by_tenant[t] = {"total_mem": 0, "alloc_mem": 0, "total_cpu": 0.0, "alloc_cpu": 0.0}
            by_tenant[t]["total_mem"] += node.total_memory
            by_tenant[t]["alloc_mem"] += node.allocated_memory
            by_tenant[t]["total_cpu"] += node.total_cpu
            by_tenant[t]["alloc_cpu"] += node.allocated_cpu

            # Runtime breakdown
            for rt in node.runtime_types:
                if rt not in by_runtime:
                    by_runtime[rt] = {"total_mem": 0, "alloc_mem": 0, "total_cpu": 0.0, "alloc_cpu": 0.0}
                by_runtime[rt]["total_mem"] += node.total_memory
                by_runtime[rt]["alloc_mem"] += node.allocated_memory
                by_runtime[rt]["total_cpu"] += node.total_cpu
                by_runtime[rt]["alloc_cpu"] += node.allocated_cpu

        mem_pct = (alloc_mem / total_mem * 100.0) if total_mem > 0 else 0.0
        cpu_pct = (alloc_cpu / total_cpu * 100.0) if total_cpu > 0 else 0.0

        return {
            "total_memory_mb": total_mem,
            "allocated_memory_mb": alloc_mem,
            "memory_utilization_percent": mem_pct,
            "total_cpu_cores": total_cpu,
            "allocated_cpu_cores": alloc_cpu,
            "cpu_utilization_percent": cpu_pct,
            "by_tenant": by_tenant,
            "by_runtime": by_runtime
        }

    def get_active_scan_count(self) -> int:
        count = 0
        for status in self._registry._execution_status.values():
            if status in ("assigned", "acknowledged"):
                count += 1
        return count

    def get_validation_failure_rate(self) -> Dict[str, Any]:
        failures = {}
        for node in self._registry._nodes.values():
            failures[node.node_id] = node.verification_failures
        return {
            "total_failures": sum(failures.values()),
            "by_node": failures
        }


# OpenTelemetry scheduler-side metrics
from opentelemetry import metrics

meter = metrics.get_meter("sentinel_scheduler")

scheduler_selection_duration = meter.create_histogram(
    name="sentinel_scheduler_selection_duration_seconds",
    description="Duration of scheduling decisions",
    unit="s"
)

scheduler_failed_matches = meter.create_counter(
    name="sentinel_scheduler_failed_matches_total",
    description="Total failed scheduling matches"
)

scheduler_capacity_exhaustions = meter.create_counter(
    name="sentinel_scheduler_capacity_exhaustions_total",
    description="Total capacity exhaustions"
)

scheduler_queue_depth = meter.create_up_down_counter(
    name="sentinel_scheduler_queue_depth",
    description="Current depth of scheduling queues"
)

scheduler_queue_rejections = meter.create_counter(
    name="sentinel_scheduler_queue_rejections_total",
    description="Total queue backpressure rejections"
)

# Phase 8 production hardening metrics
autoscaler_scale_up = meter.create_counter(
    name="sentinel_autoscaler_scale_up_total",
    description="Total autoscaler scale up recommendations emitted"
)

autoscaler_scale_down = meter.create_counter(
    name="sentinel_autoscaler_scale_down_total",
    description="Total autoscaler scale down recommendations emitted"
)

autoscaler_recommendations = meter.create_counter(
    name="sentinel_autoscaler_recommendations_total",
    description="Total scale recommendations evaluated and emitted"
)

firecracker_jailer_start_failures = meter.create_counter(
    name="sentinel_firecracker_jailer_start_failures_total",
    description="Total start failures for Firecracker jailed microVMs"
)

# Phase 9 distributed resiliency and upgrade metrics
lease_acquisition_success = meter.create_counter(
    name="sentinel_lease_acquisition_success_total",
    description="Total successful lease acquisitions"
)

lease_renewal_failure = meter.create_counter(
    name="sentinel_lease_renewal_failure_total",
    description="Total lease renewal failures"
)

consumer_group_pending_depth = meter.create_up_down_counter(
    name="sentinel_consumer_group_pending_depth",
    description="Current pending depth of consumer group"
)

stuck_message_claim_rate = meter.create_counter(
    name="sentinel_stuck_message_claim_rate_total",
    description="Total stuck messages claimed"
)

regional_routing_rejection_count = meter.create_counter(
    name="sentinel_regional_routing_rejection_total",
    description="Total regional routing rejections"
)

orphan_recovery_quarantine_count = meter.create_counter(
    name="sentinel_orphan_recovery_quarantine_total",
    description="Total executions quarantined during orphan recovery"
)

rolling_upgrade_drain_duration = meter.create_histogram(
    name="sentinel_rolling_upgrade_drain_duration_seconds",
    description="Duration of node draining during rolling upgrades",
    unit="s"
)
