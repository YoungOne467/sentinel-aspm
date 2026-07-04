import json
import logging
import asyncio
from typing import AsyncGenerator, List, Tuple
from datetime import datetime
import redis.asyncio as aioredis

from .interfaces import EventBus
from .envelope import EventEnvelope

logger = logging.getLogger(__name__)

class RedisStreamEventBus(EventBus):
    """Redis Stream-backed implementation of the EventBus, enabling multi-node messaging."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._client = aioredis.from_url(redis_url, decode_responses=True)

    def _serialize_envelope(self, envelope: EventEnvelope) -> str:
        return json.dumps({
            "event_id": envelope.event_id,
            "event_type": envelope.event_type,
            "trace_id": envelope.trace_id,
            "correlation_id": envelope.correlation_id,
            "tenant_id": envelope.tenant_id,
            "timestamp": envelope.timestamp.isoformat(),
            "schema_version": envelope.schema_version,
            "source_context": envelope.source_context,
            "payload": envelope.payload
        })

    def _deserialize_envelope(self, raw_data: str) -> EventEnvelope:
        data = json.loads(raw_data)
        return EventEnvelope(
            event_id=data["event_id"],
            event_type=data["event_type"],
            trace_id=data["trace_id"],
            correlation_id=data["correlation_id"],
            tenant_id=data["tenant_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            schema_version=data["schema_version"],
            source_context=data["source_context"],
            payload=data["payload"]
        )

    async def publish(self, topic: str, envelope: EventEnvelope) -> None:
        """Publishes an EventEnvelope to the specified stream topic."""
        serialized = self._serialize_envelope(envelope)
        # We write events into a Redis Stream
        await self._client.xadd(topic, {"envelope": serialized})
        logger.debug(f"Event {envelope.event_type} published to stream {topic}")

    async def subscribe(self, topic: str) -> AsyncGenerator[EventEnvelope, None]:
        """Subscribes to a stream topic, polling and yielding EventEnvelopes."""
        last_id = "0"
        
        # Ensure the stream exists
        try:
            await self._client.xgroup_create(topic, "sentinel_group", id="0", mkstream=True)
        except Exception:
            # Group already exists or stream was made automatically
            pass

        while True:
            try:
                # Read new messages from the stream
                streams = await self._client.xread({topic: last_id}, count=10, block=1000)
                if streams:
                    for _, messages in streams:
                        for message_id, message_data in messages:
                            last_id = message_id
                            raw_envelope = message_data.get("envelope")
                            if raw_envelope:
                                yield self._deserialize_envelope(raw_envelope)
            except aioredis.RedisError as e:
                logger.error(f"RedisStreamEventBus subscription error on {topic}: {e}")
                await asyncio.sleep(1)

    async def subscribe_group(self, topic: str, group_name: str, consumer_name: str) -> AsyncGenerator[tuple[str, EventEnvelope], None]:
        """Subscribes to a topic using a consumer group, yielding (message_id, EventEnvelope)."""
        try:
            await self._client.xgroup_create(topic, group_name, id="0", mkstream=True)
        except Exception:
            pass

        read_pending = True
        while True:
            try:
                if read_pending:
                    streams = await self._client.xreadgroup(
                        groupname=group_name,
                        consumername=consumer_name,
                        streams={topic: "0"},
                        count=10
                    )
                    if not streams:
                        read_pending = False
                        continue
                    
                    has_pending = False
                    for _, messages in streams:
                        if messages:
                            has_pending = True
                            for message_id, message_data in messages:
                                raw_envelope = message_data.get("envelope")
                                if raw_envelope:
                                    yield message_id, self._deserialize_envelope(raw_envelope)
                    if not has_pending:
                        read_pending = False
                else:
                    streams = await self._client.xreadgroup(
                        groupname=group_name,
                        consumername=consumer_name,
                        streams={topic: ">"},
                        count=10,
                        block=1000
                    )
                    if streams:
                        for _, messages in streams:
                            for message_id, message_data in messages:
                                raw_envelope = message_data.get("envelope")
                                if raw_envelope:
                                    yield message_id, self._deserialize_envelope(raw_envelope)
            except aioredis.RedisError as e:
                logger.error(f"RedisStreamEventBus subscribe_group error on {topic}: {e}")
                await asyncio.sleep(1)

    async def acknowledge(self, topic: str, group_name: str, message_id: str) -> None:
        """Acknowledges message processing completion in a consumer group."""
        try:
            await self._client.xack(topic, group_name, message_id)
        except Exception as e:
            logger.error(f"Failed to acknowledge message {message_id} on {topic}: {e}")

    async def claim_stuck_messages(self, topic: str, group_name: str, min_idle_time_ms: int, consumer_name: str) -> List[tuple[str, EventEnvelope]]:
        """Claims messages that have been pending/idle longer than threshold."""
        claimed_list = []
        try:
            pending_info = await self._client.xpending_range(
                name=topic,
                groupname=group_name,
                min="-",
                max="+",
                count=100
            )
            if not pending_info:
                return []
            
            for p in pending_info:
                msg_id = p["message_id"]
                idle_time = p["time_since_delivered"]
                if idle_time >= min_idle_time_ms:
                    res = await self._client.xclaim(
                        name=topic,
                        groupname=group_name,
                        consumername=consumer_name,
                        min_idle_time=min_idle_time_ms,
                        message_ids=[msg_id]
                    )
                    if res:
                        for claimed_id, message_data in res:
                            raw_envelope = message_data.get("envelope")
                            if raw_envelope:
                                claimed_list.append((claimed_id, self._deserialize_envelope(raw_envelope)))
        except Exception as e:
            logger.error(f"Failed to claim stuck messages on {topic}: {e}")
        return claimed_list
