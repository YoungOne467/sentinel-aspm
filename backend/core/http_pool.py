import httpx
import logging
import asyncio
from typing import Optional

logger = logging.getLogger(__name__)

class HTTPClientPool:
    """
    Centralized, thread-safe connection-pooled HTTPX AsyncClient manager.
    Prevents socket exhaustion by reusing connections, setting global limits, 
    and enforcing default timeouts.
    """
    _client: Optional[httpx.AsyncClient] = None
    _lock = asyncio.Lock()

    @classmethod
    async def get_client(cls) -> httpx.AsyncClient:
        """
        Retrieves the shared connection-pooled AsyncClient instance.
        Lazy-initializes the pool under lock control on first access.
        """
        if cls._client is None:
            async with cls._lock:
                if cls._client is None:
                    # Enforce strict limits to protect OS resource thresholds
                    limits = httpx.Limits(
                        max_connections=100,
                        max_keepalive_connections=20,
                        keepalive_expiry=30.0
                    )
                    # Configure sensible default timeouts for DAST scan probes
                    timeout = httpx.Timeout(
                        connect=10.0,
                        read=30.0,
                        write=30.0,
                        pool=10.0
                    )
                    # Disable SSL verification globally to prevent failures on untrusted staging sites
                    cls._client = httpx.AsyncClient(
                        limits=limits,
                        timeout=timeout,
                        follow_redirects=True,
                        verify=False
                    )
                    logger.info("Centralized connection-pooled HTTPX AsyncClient initialized.")
        return cls._client

    @classmethod
    async def close(cls):
        """
        Closes the active AsyncClient session and releases all pooled resources.
        Should be called during backend lifespan shutdown.
        """
        if cls._client is not None:
            async with cls._lock:
                if cls._client is not None:
                    await cls._client.aclose()
                    cls._client = None
                    logger.info("Centralized connection-pooled HTTPX AsyncClient terminated.")
