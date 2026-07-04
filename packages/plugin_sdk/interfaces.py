from abc import ABC, abstractmethod
from typing import List
from dataclasses import dataclass

@dataclass
class CapabilityDecision:
    allowed: bool
    denied_capabilities: List[str]
    reason: str

class PluginCapabilityResolver(ABC):
    """Validates requested capabilities against allowed policies."""
    
    @abstractmethod
    async def validate(self, requested_capabilities: List[str], plugin_id: str, manifest_data: dict = None, signature_block: dict = None) -> CapabilityDecision:
        """
        Capabilities examples:
        - network:external
        - secret:jira
        - filesystem:read
        """
        pass
