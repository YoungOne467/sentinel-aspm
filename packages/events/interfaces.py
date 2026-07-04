from abc import ABC, abstractmethod
from typing import AsyncGenerator, List
from .envelope import EventEnvelope

class EventBus(ABC):
    """Abstract Event Bus interface decoupling domain events from transit implementation details."""
    
    @abstractmethod
    async def publish(self, topic: str, envelope: EventEnvelope) -> None:
        """Publishes a validated and trace-correlated EventEnvelope to a topic."""
        pass

    @abstractmethod
    async def subscribe(self, topic: str) -> AsyncGenerator[EventEnvelope, None]:
        """Subscribes to a topic, yielding incoming EventEnvelopes asynchronously."""
        pass

    @abstractmethod
    async def subscribe_group(self, topic: str, group_name: str, consumer_name: str) -> AsyncGenerator[tuple[str, EventEnvelope], None]:
        """Subscribes to a topic using a consumer group, yielding (message_id, EventEnvelope)."""
        pass

    @abstractmethod
    async def acknowledge(self, topic: str, group_name: str, message_id: str) -> None:
        """Acknowledges message processing completion in a consumer group."""
        pass

    @abstractmethod
    async def claim_stuck_messages(self, topic: str, group_name: str, min_idle_time_ms: int, consumer_name: str) -> List[tuple[str, EventEnvelope]]:
        """Claims messages that have been pending/idle longer than threshold."""
        pass
