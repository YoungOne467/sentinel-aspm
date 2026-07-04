import time
import logging
from abc import ABC, abstractmethod
from typing import Optional, Any
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

class LeaseManager(ABC):
    """
    Distributed lease manager interface for active-passive leader election.
    """
    @abstractmethod
    async def acquire_lease(self, lease_name: str, holder_id: str, duration_sec: float) -> bool:
        """
        Attempts to acquire or renew the lease. Returns True if successful.
        """
        pass

    @abstractmethod
    async def release_lease(self, lease_name: str, holder_id: str) -> None:
        """
        Releases the lease if held by the holder.
        """
        pass

    @abstractmethod
    async def is_lease_active(self, lease_name: str, holder_id: str) -> bool:
        """
        Checks if the lease is currently active and held by the holder.
        """
        pass


class InMemoryLeaseManager(LeaseManager):
    """
    In-memory lease manager for local development and unit tests.
    """
    def __init__(self):
        self._leases = {}  # lease_name -> (holder_id, expires_at)

    async def acquire_lease(self, lease_name: str, holder_id: str, duration_sec: float) -> bool:
        now = time.time()
        if lease_name in self._leases:
            curr_holder, expires_at = self._leases[lease_name]
            if now < expires_at and curr_holder != holder_id:
                return False
        self._leases[lease_name] = (holder_id, now + duration_sec)
        return True

    async def release_lease(self, lease_name: str, holder_id: str) -> None:
        if lease_name in self._leases:
            curr_holder, _ = self._leases[lease_name]
            if curr_holder == holder_id:
                self._leases.pop(lease_name)

    async def is_lease_active(self, lease_name: str, holder_id: str) -> bool:
        now = time.time()
        if lease_name not in self._leases:
            return False
        curr_holder, expires_at = self._leases[lease_name]
        return curr_holder == holder_id and now < expires_at


class RedisLeaseManager(LeaseManager):
    """
    Redis-backed lease manager with Lua-script atomic operations.
    """
    def __init__(self, redis_client: Optional[Any] = None, redis_url: str = "redis://localhost:6379/0"):
        if redis_client is not None:
            self._client = redis_client
        else:
            self._client = aioredis.from_url(redis_url, decode_responses=True)

    async def acquire_lease(self, lease_name: str, holder_id: str, duration_sec: float) -> bool:
        key = f"lease:{lease_name}"
        lua_script = """
        local key = KEYS[1]
        local holder = ARGV[1]
        local duration = tonumber(ARGV[2])
        local current = redis.call('get', key)
        if not current or current == holder then
            redis.call('set', key, holder, 'ex', duration)
            return 1
        else
            return 0
        end
        """
        try:
            res = await self._client.eval(lua_script, 1, key, holder_id, int(duration_sec))
            return res == 1
        except Exception as e:
            logger.warning(f"Failed to acquire lease in Redis: {e}")
            return False

    async def release_lease(self, lease_name: str, holder_id: str) -> None:
        key = f"lease:{lease_name}"
        lua_script = """
        local key = KEYS[1]
        local holder = ARGV[1]
        if redis.call('get', key) == holder then
            redis.call('del', key)
            return 1
        else
            return 0
        end
        """
        try:
            await self._client.eval(lua_script, 1, key, holder_id)
        except Exception as e:
            logger.warning(f"Failed to release lease in Redis: {e}")

    async def is_lease_active(self, lease_name: str, holder_id: str) -> bool:
        key = f"lease:{lease_name}"
        try:
            curr = await self._client.get(key)
            return curr == holder_id
        except Exception:
            return False
