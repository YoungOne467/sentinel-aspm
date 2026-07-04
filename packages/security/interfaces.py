from abc import ABC, abstractmethod
from typing import Optional
from enum import Enum

class SecretProviderPriority(Enum):
    ENVIRONMENT = "environment"
    EXTERNAL = "external"
    DATABASE = "database"

class SecretProvider(ABC):
    """Abstract provider for secret retrieval."""
    
    @abstractmethod
    async def get_secret(self, key: str) -> Optional[str]:
        pass
    
    @abstractmethod
    async def supports_rotation(self) -> bool:
        pass
    
    @abstractmethod
    async def supports_versioning(self) -> bool:
        pass

class SecretProviderChain(ABC):
    """
    Resolves secrets deterministically based on configuration precedence:
    Environment -> External Vault -> Database -> Failure.
    """
    
    @abstractmethod
    def register_provider(self, provider: SecretProvider, priority: SecretProviderPriority) -> None:
        pass
        
    @abstractmethod
    async def resolve(self, key: str) -> Optional[str]:
        pass
