import logging
import time
from typing import Dict, List, Any, Optional
from collections import deque
from packages.observability.metrics import scheduler_queue_depth, scheduler_queue_rejections

logger = logging.getLogger(__name__)

_PRIORITY_MAP = {
    "high": 3,
    "medium": 2,
    "low": 1
}

class WorkloadQueueManager:
    """
    Manages tenant-scoped bounded workload queues with round-robin dequeue fairness.
    Enforces a strict max depth per tenant and supports priority tail-drop.
    """
    def __init__(self, max_depth: int = 100):
        self.max_depth = max_depth
        self._queues: Dict[str, deque] = {}
        self._tenant_order: List[str] = []

    def get_queue_depth(self, tenant_id: str) -> int:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")
        return len(self._queues.get(tenant_id, deque()))

    def get_total_depth(self) -> int:
        return sum(len(q) for q in self._queues.values())

    def enqueue(self, tenant_id: str, item: Any, tenant_tier: str = "standard", runtime_type: str = "standard", priority: str = "low") -> bool:
        if not tenant_id or tenant_id.strip() == "":
            raise ValueError("tenant_id must be explicit and non-empty")

        pri_str = str(priority).lower()
        pri_val = _PRIORITY_MAP.get(pri_str, 1)

        if tenant_id not in self._queues:
            self._queues[tenant_id] = deque()

        queue = self._queues[tenant_id]

        # Enforce Tenant-Local Tail-Drop
        if len(queue) >= self.max_depth:
            lowest_idx = -1
            lowest_pri = pri_val

            # Search only within this tenant's queue
            for idx, entry in enumerate(queue):
                if entry["priority"] < lowest_pri:
                    lowest_pri = entry["priority"]
                    lowest_idx = idx

            if lowest_idx != -1:
                # Evict the lowest-priority item from this tenant's queue
                l = list(queue)
                evicted = l.pop(lowest_idx)
                self._queues[tenant_id] = deque(l)

                # Record metrics updates
                scheduler_queue_depth.add(-1, {
                    "tenant_tier": evicted["tenant_tier"],
                    "runtime_type": evicted["runtime_type"]
                })
                scheduler_queue_rejections.add(1, {
                    "tenant_tier": evicted["tenant_tier"],
                    "runtime_type": evicted["runtime_type"]
                })
                logger.warning(
                    f"Tenant-Local Tail-Drop: Evicted lowest priority workload (priority: {evicted['priority']}) "
                    f"from tenant {tenant_id}'s queue to make room for incoming priority {pri_val}"
                )
            else:
                # Rejections metrics without tenant_id label
                scheduler_queue_rejections.add(1, {
                    "tenant_tier": tenant_tier,
                    "runtime_type": runtime_type
                })
                logger.warning(f"Queue depth limit reached for tenant {tenant_id} (limit: {self.max_depth}). Rejected.")
                return False

        # Add to the queue
        self._queues[tenant_id].append({
            "item": item,
            "tenant_tier": tenant_tier,
            "runtime_type": runtime_type,
            "priority": pri_val,
            "enqueue_time": time.time()
        })

        if tenant_id not in self._tenant_order:
            self._tenant_order.append(tenant_id)

        # Update queue depth metric (no tenant_id label to avoid cardinality protection issues)
        scheduler_queue_depth.add(1, {
            "tenant_tier": tenant_tier,
            "runtime_type": runtime_type
        })
        return True

    def dequeue(self) -> Optional[Any]:
        active_tenants = [t for t, q in self._queues.items() if q]
        if not active_tenants:
            return None

        # Clean tenant order to contain only active tenants
        self._tenant_order = [t for t in self._tenant_order if t in active_tenants]
        for t in active_tenants:
            if t not in self._tenant_order:
                self._tenant_order.append(t)

        if not self._tenant_order:
            return None

        # Pop next tenant in round-robin sequence
        next_tenant = self._tenant_order.pop(0)
        queue = self._queues[next_tenant]

        # Priority first, FIFO second: Find first occurrence of highest priority
        highest_pri = -1
        highest_idx = -1
        for idx, entry in enumerate(queue):
            if entry["priority"] > highest_pri:
                highest_pri = entry["priority"]
                highest_idx = idx

        # Dequeue the item
        l = list(queue)
        entry = l.pop(highest_idx)
        self._queues[next_tenant] = deque(l)

        if self._queues[next_tenant]:
            self._tenant_order.append(next_tenant)

        # Update metric
        scheduler_queue_depth.add(-1, {
            "tenant_tier": entry["tenant_tier"],
            "runtime_type": entry["runtime_type"]
        })

        return entry["item"]

    def clear(self) -> None:
        """Clears all queues and resets round-robin order."""
        for tenant_id, q in self._queues.items():
            while q:
                entry = q.popleft()
                scheduler_queue_depth.add(-1, {
                    "tenant_tier": entry["tenant_tier"],
                    "runtime_type": entry["runtime_type"]
                })
        self._queues.clear()
        self._tenant_order.clear()
