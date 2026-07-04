import time
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any

from packages.execution.fleet import FleetRegistry
from packages.execution.queues import WorkloadQueueManager
from packages.observability.metrics import (
    autoscaler_scale_up,
    autoscaler_scale_down,
    autoscaler_recommendations
)

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class ScaleRecommendation:
    recommendation_type: str  # "scale_up" | "scale_down" | "none"
    desired_node_count: int
    reason: str
    timestamp: float

class FleetAutoscaler:
    """
    Advisory-only autoscaler evaluating cluster utilization and queue depths.
    Emits ScaleRecommendations for the Control Plane to execute.
    """
    def __init__(
        self,
        registry: FleetRegistry,
        queue_manager: WorkloadQueueManager,
        scale_up_intervals: int = 3,
        scale_down_cooldown: float = 300.0,
        min_nodes: int = 1,
        max_nodes: int = 10
    ):
        self.registry = registry
        self.queue_manager = queue_manager
        self.scale_up_intervals = scale_up_intervals
        self.scale_down_cooldown = scale_down_cooldown
        self.min_nodes = min_nodes
        self.max_nodes = max_nodes

        # Hysteresis state tracking
        self._consecutive_scale_up_checks = 0
        self._last_scale_down_time = time.time()
        self._scale_down_active = False

        # Deduplication state
        self._last_recommendation: Optional[ScaleRecommendation] = None

    async def evaluate(self) -> Optional[ScaleRecommendation]:
        """
        Evaluates registry utilization and queue metrics to determine scaling needs.
        Returns a new ScaleRecommendation, or None if no change is needed or if deduplicated.
        """
        now = time.time()
        total_nodes = len(self.registry._nodes)
        
        # Calculate memory and CPU utilization
        total_mem = sum(n.total_memory for n in self.registry._nodes.values())
        alloc_mem = sum(n.allocated_memory for n in self.registry._nodes.values())
        total_cpu = sum(n.total_cpu for n in self.registry._nodes.values())
        alloc_cpu = sum(n.allocated_cpu for n in self.registry._nodes.values())

        mem_util = (alloc_mem / total_mem) if total_mem > 0 else 0.0
        cpu_util = (alloc_cpu / total_cpu) if total_cpu > 0 else 0.0
        max_util = max(mem_util, cpu_util)

        total_queued = self.queue_manager.get_total_depth()

        recommendation_type = "none"
        desired_node_count = total_nodes
        reason = "Fleet status normal"

        # 1. Scale Up Trigger (utilization > 80% or queue depth > 5)
        if max_util > 0.80 or total_queued > 5:
            self._consecutive_scale_up_checks += 1
            self._scale_down_active = False  # Reset scale down cooldown
            
            if self._consecutive_scale_up_checks >= self.scale_up_intervals:
                # Recommend scale up
                recommendation_type = "scale_up"
                desired_node_count = min(self.max_nodes, total_nodes + 1)
                reason = f"High utilization ({max_util:.1%}) or queued workloads ({total_queued}) sustained for {self._consecutive_scale_up_checks} checks"
        else:
            self._consecutive_scale_up_checks = 0

            # 2. Scale Down Trigger (utilization < 20% and queue depth == 0)
            if max_util < 0.20 and total_queued == 0 and total_nodes > self.min_nodes:
                if not self._scale_down_active:
                    self._scale_down_active = True
                    self._last_scale_down_time = now
                elif now - self._last_scale_down_time >= self.scale_down_cooldown:
                    recommendation_type = "scale_down"
                    desired_node_count = max(self.min_nodes, total_nodes - 1)
                    reason = f"Low utilization ({max_util:.1%}) sustained for cooldown of {self.scale_down_cooldown}s"
            else:
                self._scale_down_active = False

        # Create recommendation object
        rec = ScaleRecommendation(
            recommendation_type=recommendation_type,
            desired_node_count=desired_node_count,
            reason=reason,
            timestamp=now
        )

        # 3. Apply Dampening / Deduplication
        if self._last_recommendation is not None:
            if (self._last_recommendation.recommendation_type == rec.recommendation_type and
                self._last_recommendation.desired_node_count == rec.desired_node_count):
                # Suppress identical recommendation
                return None

        self._last_recommendation = rec

        # Emit metrics (only for actual non-deduplicated recommendations)
        autoscaler_recommendations.add(1)
        if rec.recommendation_type == "scale_up":
            autoscaler_scale_up.add(1)
        elif rec.recommendation_type == "scale_down":
            autoscaler_scale_down.add(1)

        return rec
