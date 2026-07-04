from abc import ABC, abstractmethod

class ObjectStore(ABC):
    """Abstract Object Store interface defining the contract for large binary payload storage."""

    @abstractmethod
    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        """Stores binary data under a key, returning the public or internal access URI."""
        pass

    @abstractmethod
    async def get(self, key: str) -> bytes:
        """Retrieves binary data stored under a key."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Deletes binary data stored under a key."""
        pass
