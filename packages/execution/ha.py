import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

from packages.execution.fleet import ReservationStore

logger = logging.getLogger(__name__)

class ActiveActiveCoordinator:
    """
    Active-active scheduler coordination optimization layer.
    Coordinates lock checks to reduce reservation collisions.
    The ReservationStore remains the authoritative concurrency boundary.
    """
    _shared_local_locks: Dict[str, tuple] = {}

    def __init__(self, reservation_store: ReservationStore, lock_client: Optional[Any] = None):
        self.reservation_store = reservation_store
        self.lock_client = lock_client

    async def acquire_coordination_lock(self, execution_id: str, ttl_sec: float = 5.0) -> bool:
        """
        Acquires a coordination lock (optimization).
        Returns True if acquired, False otherwise.
        """
        if self.lock_client is not None:
            try:
                # Clustered/Distributed Redis Set NX lock simulation
                key = f"coord_lock:{execution_id}"
                success = await self.lock_client.set(key, "locked", ex=int(ttl_sec), nx=True)
                return bool(success)
            except Exception as e:
                logger.warning(f"Failed to set coordinator lock in Redis: {e}")
                return False
        else:
            # InMemory local fallback for tests
            now = time.time()
            if execution_id in self._shared_local_locks:
                locked_at, duration = self._shared_local_locks[execution_id]
                if now - locked_at < duration:
                    return False
            self._shared_local_locks[execution_id] = (now, ttl_sec)
            return True

    async def release_coordination_lock(self, execution_id: str) -> None:
        if self.lock_client is not None:
            try:
                key = f"coord_lock:{execution_id}"
                await self.lock_client.delete(key)
            except Exception:
                pass
        else:
            self._shared_local_locks.pop(execution_id, None)


class DatabaseHealthProvider(ABC):
    """
    Interface for exposing control-plane database status to scheduling components.
    """
    @abstractmethod
    async def get_health_state(self) -> str:
        """
        Returns one of: 'healthy', 'degraded', or 'unavailable'.
        """
        pass

class SimpleDatabaseHealthProvider(DatabaseHealthProvider):
    def __init__(self, initial_state: str = "healthy"):
        self._state = initial_state

    def set_state(self, state: str) -> None:
        if state not in ("healthy", "degraded", "unavailable"):
            raise ValueError("Invalid DB health state")
        self._state = state

    async def get_health_state(self) -> str:
        return self._state
