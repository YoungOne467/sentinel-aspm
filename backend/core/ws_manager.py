import asyncio
import logging
import json
import os
from typing import List, Dict
from fastapi import WebSocket
import redis.asyncio as redis

logger = logging.getLogger("sentinel.ws_manager")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

class ConnectionManager:
    def __init__(self):
        self._connections: List[WebSocket] = []
        self._queues: Dict[WebSocket, asyncio.Queue] = {}
        self._write_tasks: Dict[WebSocket, asyncio.Task] = {}
        self._redis = redis.from_url(REDIS_URL)

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        queue = asyncio.Queue(maxsize=100)  # Buffer up to 100 messages per client
        self._queues[ws] = queue
        self._write_tasks[ws] = asyncio.create_task(self._client_writer(ws, queue))
        logger.info("WS connected. Total: %d", len(self._connections))

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)
        if ws in self._queues:
            self._queues.pop(ws, None)
        task = self._write_tasks.pop(ws, None)
        if task:
            task.cancel()
        logger.info("WS disconnected. Total: %d", len(self._connections))

    async def _client_writer(self, ws: WebSocket, queue: asyncio.Queue):
        """Dedicated background writer task per connection."""
        try:
            while True:
                msg = await queue.get()
                try:
                    await ws.send_json(msg)
                except Exception as exc:
                    logger.debug("Error sending JSON to client, disconnecting: %s", exc)
                    break
                queue.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            self.disconnect(ws)

    async def broadcast(self, message: dict):
        """Enqueue message for all active connections. Non-blocking."""
        for ws, queue in list(self._queues.items()):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                logger.warning("WebSocket queue full for client, disconnecting slow client.")
                self.disconnect(ws)

    async def listen_to_redis(self):
        """Background task that subscribes to Redis and broadcasts incoming telemetry."""
        retry_delay = 2
        while True:
            pubsub = None
            try:
                pubsub = self._redis.pubsub()
                await pubsub.subscribe("sentinel_telemetry")
                logger.info("Subscribed to Redis channel 'sentinel_telemetry'")
                retry_delay = 2  # Reset delay on successful connection
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        try:
                            data = json.loads(message["data"])
                            await self.broadcast(data)
                        except Exception as e:
                            logger.error("Failed to parse Redis telemetry message: %s", e)
            except asyncio.CancelledError:
                logger.info("Redis listener cancelled")
                break
            except Exception as e:
                logger.warning("Redis connection/subscription failed: %s. Retrying in %ds...", e, retry_delay)
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)
            finally:
                if pubsub:
                    try:
                        await pubsub.unsubscribe("sentinel_telemetry")
                    except Exception:
                        pass
                    try:
                        await pubsub.close()
                    except Exception:
                        pass

    @property
    def count(self) -> int:
        return len(self._connections)

manager = ConnectionManager()
