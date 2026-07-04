from abc import ABC, abstractmethod
from enum import Enum
from typing import Set

class IsolationLevel(Enum):
    STANDARD = "standard"
    GVISOR = "gvisor"
    FIRECRACKER = "firecracker"

class IsolationMatchPolicy(ABC):
    @abstractmethod
    async def required_isolation(self, capabilities: Set[str]) -> IsolationLevel:
        """
        Determines the required isolation level based on the set of capabilities.
        """
        pass

class DefaultIsolationMatchPolicy(IsolationMatchPolicy):
    async def required_isolation(self, capabilities: Set[str]) -> IsolationLevel:
        # Check capability risk mapping
        if "network:external" in capabilities:
            return IsolationLevel.FIRECRACKER
        elif "filesystem:write" in capabilities:
            return IsolationLevel.GVISOR
        else:
            return IsolationLevel.STANDARD
