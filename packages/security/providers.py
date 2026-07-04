import os
from typing import Optional, Dict
from core.database import AsyncSessionLocal
from core.models import PlatformSettings
from packages.audit.emitter import audit_emitter
from packages.audit.events import SecretResolvedEvent, SecretResolutionFailedEvent
from .interfaces import SecretProvider, SecretProviderChain, SecretProviderPriority

class EnvironmentSecretProvider(SecretProvider):
    async def get_secret(self, key: str) -> Optional[str]:
        return os.environ.get(key)
    
    async def supports_rotation(self) -> bool:
        return False
        
    async def supports_versioning(self) -> bool:
        return False

class DatabaseSecretProvider(SecretProvider):
    async def get_secret(self, key: str) -> Optional[str]:
        async with AsyncSessionLocal() as session:
            settings = await session.get(PlatformSettings, "default")
            if not settings:
                return None
            if hasattr(settings, key):
                return getattr(settings, key)
            return None

    async def supports_rotation(self) -> bool:
        return False
        
    async def supports_versioning(self) -> bool:
        return False

class DefaultSecretProviderChain(SecretProviderChain):
    # Precedence maps priority to integer for sorting
    PRECEDENCE = {
        SecretProviderPriority.ENVIRONMENT: 1,
        SecretProviderPriority.EXTERNAL: 2,
        SecretProviderPriority.DATABASE: 3
    }

    def __init__(self):
        self._providers: Dict[SecretProviderPriority, SecretProvider] = {}
        
    def register_provider(self, provider: SecretProvider, priority: SecretProviderPriority) -> None:
        self._providers[priority] = provider
        
    async def resolve(self, key: str) -> Optional[str]:
        # Sort registered providers by precedence
        sorted_priorities = sorted(self._providers.keys(), key=lambda p: self.PRECEDENCE[p])
        
        for priority in sorted_priorities:
            provider = self._providers[priority]
            value = await provider.get_secret(key)
            if value is not None:
                await audit_emitter.emit(
                    SecretResolvedEvent(
                        name="SecretResolved",
                        payload={"key": key, "provider": provider.__class__.__name__, "success": True}
                    ),
                    actor="system"
                )
                return value
                
        # Failed
        await audit_emitter.emit(
            SecretResolutionFailedEvent(
                name="SecretResolutionFailed",
                payload={"key": key}
            ),
            actor="system"
        )
        return None

secret_chain = DefaultSecretProviderChain()
secret_chain.register_provider(EnvironmentSecretProvider(), SecretProviderPriority.ENVIRONMENT)
secret_chain.register_provider(DatabaseSecretProvider(), SecretProviderPriority.DATABASE)
