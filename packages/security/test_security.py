"""Tests for the security bounded context: secret chain priority resolution and no execution leak."""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.security.interfaces import (
    SecretProvider,
    SecretProviderChain,
    SecretProviderPriority,
)


# ---------------------------------------------------------------------------
# Concrete test providers (no real DB or vault)
# ---------------------------------------------------------------------------

class StubSecretProvider(SecretProvider):
    """In-memory secret provider for testing."""

    def __init__(self, secrets: dict = None):
        self._secrets = secrets or {}

    async def get_secret(self, key: str):
        return self._secrets.get(key)

    async def supports_rotation(self):
        return False

    async def supports_versioning(self):
        return False


# ---------------------------------------------------------------------------
# DefaultSecretProviderChain - priority resolution tests
# ---------------------------------------------------------------------------

class TestSecretChainPriority:
    @pytest.mark.asyncio
    @patch("packages.security.providers.audit_emitter", new_callable=MagicMock)
    async def test_environment_takes_precedence_over_database(self, mock_audit):
        """Environment provider (priority 1) should resolve before Database (priority 3)."""
        mock_audit.emit = AsyncMock()

        from packages.security.providers import DefaultSecretProviderChain

        chain = DefaultSecretProviderChain()
        env_provider = StubSecretProvider({"API_KEY": "env-value"})
        db_provider = StubSecretProvider({"API_KEY": "db-value"})

        chain.register_provider(env_provider, SecretProviderPriority.ENVIRONMENT)
        chain.register_provider(db_provider, SecretProviderPriority.DATABASE)

        result = await chain.resolve("API_KEY")
        assert result == "env-value"

    @pytest.mark.asyncio
    @patch("packages.security.providers.audit_emitter", new_callable=MagicMock)
    async def test_falls_through_to_database(self, mock_audit):
        """If environment provider returns None, the chain should fall through to database."""
        mock_audit.emit = AsyncMock()

        from packages.security.providers import DefaultSecretProviderChain

        chain = DefaultSecretProviderChain()
        env_provider = StubSecretProvider({})  # No secrets
        db_provider = StubSecretProvider({"DB_PASSWORD": "db-secret"})

        chain.register_provider(env_provider, SecretProviderPriority.ENVIRONMENT)
        chain.register_provider(db_provider, SecretProviderPriority.DATABASE)

        result = await chain.resolve("DB_PASSWORD")
        assert result == "db-secret"

    @pytest.mark.asyncio
    @patch("packages.security.providers.audit_emitter", new_callable=MagicMock)
    async def test_external_takes_precedence_over_database(self, mock_audit):
        """External vault (priority 2) should resolve before Database (priority 3)."""
        mock_audit.emit = AsyncMock()

        from packages.security.providers import DefaultSecretProviderChain

        chain = DefaultSecretProviderChain()
        external_provider = StubSecretProvider({"VAULT_TOKEN": "vault-value"})
        db_provider = StubSecretProvider({"VAULT_TOKEN": "db-value"})

        chain.register_provider(external_provider, SecretProviderPriority.EXTERNAL)
        chain.register_provider(db_provider, SecretProviderPriority.DATABASE)

        result = await chain.resolve("VAULT_TOKEN")
        assert result == "vault-value"

    @pytest.mark.asyncio
    @patch("packages.security.providers.audit_emitter", new_callable=MagicMock)
    async def test_returns_none_when_no_provider_has_secret(self, mock_audit):
        """If no provider can resolve a key, the chain should return None."""
        mock_audit.emit = AsyncMock()

        from packages.security.providers import DefaultSecretProviderChain

        chain = DefaultSecretProviderChain()
        chain.register_provider(StubSecretProvider({}), SecretProviderPriority.ENVIRONMENT)
        chain.register_provider(StubSecretProvider({}), SecretProviderPriority.DATABASE)

        result = await chain.resolve("NONEXISTENT_SECRET")
        assert result is None

    @pytest.mark.asyncio
    @patch("packages.security.providers.audit_emitter", new_callable=MagicMock)
    async def test_full_chain_precedence_env_external_db(self, mock_audit):
        """Full 3-level chain: Environment > External > Database."""
        mock_audit.emit = AsyncMock()

        from packages.security.providers import DefaultSecretProviderChain

        chain = DefaultSecretProviderChain()
        chain.register_provider(
            StubSecretProvider({"KEY": "from-env"}),
            SecretProviderPriority.ENVIRONMENT,
        )
        chain.register_provider(
            StubSecretProvider({"KEY": "from-vault"}),
            SecretProviderPriority.EXTERNAL,
        )
        chain.register_provider(
            StubSecretProvider({"KEY": "from-db"}),
            SecretProviderPriority.DATABASE,
        )

        result = await chain.resolve("KEY")
        assert result == "from-env"


# ---------------------------------------------------------------------------
# No execution leak: security context never leaks execution details
# ---------------------------------------------------------------------------

class TestNoExecutionLeak:
    def test_secret_provider_has_no_execute_method(self):
        """SecretProvider interface must not expose any execution capability."""
        provider = StubSecretProvider()
        assert not hasattr(provider, "execute")
        assert not hasattr(provider, "run")
        assert not hasattr(provider, "shell")

    def test_secret_chain_has_no_execute_method(self):
        """SecretProviderChain must not expose any execution capability."""
        assert not hasattr(SecretProviderChain, "execute")
        assert not hasattr(SecretProviderChain, "run")
        assert not hasattr(SecretProviderChain, "shell")

    @pytest.mark.asyncio
    @patch("packages.security.providers.audit_emitter", new_callable=MagicMock)
    async def test_resolve_emits_audit_event_on_success(self, mock_audit):
        """Successful resolution should emit a SecretResolved audit event."""
        mock_audit.emit = AsyncMock()

        from packages.security.providers import DefaultSecretProviderChain

        chain = DefaultSecretProviderChain()
        chain.register_provider(
            StubSecretProvider({"KEY": "value"}),
            SecretProviderPriority.ENVIRONMENT,
        )

        await chain.resolve("KEY")
        mock_audit.emit.assert_awaited_once()
        event = mock_audit.emit.call_args[0][0]
        assert event.name == "SecretResolved"

    @pytest.mark.asyncio
    @patch("packages.security.providers.audit_emitter", new_callable=MagicMock)
    async def test_resolve_emits_audit_event_on_failure(self, mock_audit):
        """Failed resolution should emit a SecretResolutionFailed audit event."""
        mock_audit.emit = AsyncMock()

        from packages.security.providers import DefaultSecretProviderChain

        chain = DefaultSecretProviderChain()
        chain.register_provider(StubSecretProvider({}), SecretProviderPriority.ENVIRONMENT)

        await chain.resolve("MISSING")
        mock_audit.emit.assert_awaited_once()
        event = mock_audit.emit.call_args[0][0]
        assert event.name == "SecretResolutionFailed"
