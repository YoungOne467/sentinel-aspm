"""Tests for the ai_governance bounded context: budget policies (Redis-mocked) and circuit breaker transitions."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.ai_governance.interfaces import PolicyContext, PolicyEvaluation, AIPolicy


# ---------------------------------------------------------------------------
# PolicyContext / PolicyEvaluation data classes
# ---------------------------------------------------------------------------

class TestPolicyDataClasses:
    def test_policy_context_defaults(self):
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        assert ctx.global_scope is False

    def test_policy_evaluation_fields(self):
        ev = PolicyEvaluation(allowed=True, reason="ok", policy_name="TestPolicy")
        assert ev.allowed is True
        assert ev.reason == "ok"
        assert ev.policy_name == "TestPolicy"


# ---------------------------------------------------------------------------
# TokenPolicy with mocked Redis
# ---------------------------------------------------------------------------

class TestTokenPolicy:
    @pytest.mark.asyncio
    async def test_token_policy_allows_within_budget(self):
        from packages.ai_governance.policies import TokenPolicy
        policy = TokenPolicy(max_tokens=1000)
        policy._redis = AsyncMock()
        policy._redis.eval = AsyncMock(return_value=1)  # Lua returns 1 = allowed

        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, requested_tokens=100)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_token_policy_denies_over_budget(self):
        from packages.ai_governance.policies import TokenPolicy
        policy = TokenPolicy(max_tokens=1000)
        policy._redis = AsyncMock()
        policy._redis.eval = AsyncMock(return_value=0)  # Lua returns 0 = denied

        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, requested_tokens=2000)
        assert result.allowed is False
        assert "exceeded" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_token_policy_bypasses_on_redis_failure(self):
        from packages.ai_governance.policies import TokenPolicy
        policy = TokenPolicy(max_tokens=1000)
        policy._redis = AsyncMock()
        policy._redis.eval = AsyncMock(side_effect=Exception("Connection refused"))

        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, requested_tokens=100)
        # Fail-open for resilience
        assert result.allowed is True
        assert "bypassed" in result.reason.lower()


# ---------------------------------------------------------------------------
# CostPolicy with mocked Redis
# ---------------------------------------------------------------------------

class TestCostPolicy:
    @pytest.mark.asyncio
    async def test_cost_policy_allows_within_budget(self):
        from packages.ai_governance.policies import CostPolicy, SimpleCostCalculator, SimplePricingModel
        policy = CostPolicy(
            max_cost_usd=100.0,
            cost_calculator=SimpleCostCalculator(),
            pricing_model=SimplePricingModel(),
        )
        policy._redis = AsyncMock()
        policy._redis.eval = AsyncMock(return_value=1)

        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, requested_tokens=10)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_cost_policy_denies_over_budget(self):
        from packages.ai_governance.policies import CostPolicy, SimpleCostCalculator, SimplePricingModel
        policy = CostPolicy(
            max_cost_usd=0.001,
            cost_calculator=SimpleCostCalculator(),
            pricing_model=SimplePricingModel(),
        )
        policy._redis = AsyncMock()
        policy._redis.eval = AsyncMock(return_value=0)

        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, requested_tokens=999999)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# RecursionPolicy / ToolCallPolicy (no Redis needed)
# ---------------------------------------------------------------------------

class TestRecursionPolicy:
    @pytest.mark.asyncio
    async def test_allows_within_depth(self):
        from packages.ai_governance.policies import DefaultRecursionPolicy
        policy = DefaultRecursionPolicy(max_depth=8)
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, current_depth=5)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_denies_exceeding_depth(self):
        from packages.ai_governance.policies import DefaultRecursionPolicy
        policy = DefaultRecursionPolicy(max_depth=8)
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, current_depth=9)
        assert result.allowed is False


class TestToolCallPolicy:
    @pytest.mark.asyncio
    async def test_allows_within_limit(self):
        from packages.ai_governance.policies import ToolCallPolicy
        policy = ToolCallPolicy(max_tool_calls=20)
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, tool_calls_count=10)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_denies_exceeding_limit(self):
        from packages.ai_governance.policies import ToolCallPolicy
        policy = ToolCallPolicy(max_tool_calls=20)
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await policy.evaluate(ctx, tool_calls_count=25)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# DefaultLatencyPolicy / DefaultErrorRatePolicy
# ---------------------------------------------------------------------------

class TestLatencyPolicy:
    @pytest.mark.asyncio
    async def test_allows_when_insufficient_samples(self):
        from packages.ai_governance.policies import DefaultLatencyPolicy
        policy = DefaultLatencyPolicy(max_latency_ms=100.0)
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        # Less than 5 samples — should always allow
        result = await policy.evaluate(ctx)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_denies_on_sustained_high_latency(self):
        from packages.ai_governance.policies import DefaultLatencyPolicy
        policy = DefaultLatencyPolicy(max_latency_ms=100.0)
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        # Record 5 high-latency samples
        for _ in range(5):
            await policy.record(ctx, latency_ms=200.0)
        result = await policy.evaluate(ctx)
        assert result.allowed is False


class TestErrorRatePolicy:
    @pytest.mark.asyncio
    async def test_allows_within_safe_range(self):
        from packages.ai_governance.policies import DefaultErrorRatePolicy
        policy = DefaultErrorRatePolicy(max_error_rate=0.5, window_size=10)
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        # Record 10 successes
        for _ in range(10):
            await policy.record(ctx, success=True)
        result = await policy.evaluate(ctx)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_denies_high_error_rate(self):
        from packages.ai_governance.policies import DefaultErrorRatePolicy
        policy = DefaultErrorRatePolicy(max_error_rate=0.5, window_size=10)
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        # Record 7 failures and 3 successes (70% error rate)
        for _ in range(7):
            await policy.record(ctx, success=False)
        for _ in range(3):
            await policy.record(ctx, success=True)
        result = await policy.evaluate(ctx)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# Circuit Breaker state transitions
# ---------------------------------------------------------------------------

class TestCircuitBreakerTransitions:
    """Test the DefaultCircuitBreaker state machine: closed -> tripped -> reset."""

    @pytest.mark.asyncio
    async def test_breaker_starts_closed(self):
        from packages.ai_governance.breaker import DefaultCircuitBreaker
        breaker = DefaultCircuitBreaker()
        assert breaker._is_tripped is False

    @pytest.mark.asyncio
    @patch("packages.ai_governance.breaker.audit_emitter", new_callable=MagicMock)
    async def test_breaker_trips_on_policy_denial(self, mock_audit):
        """When a sub-policy denies, the breaker should trip and emit an audit event."""
        from packages.ai_governance.breaker import DefaultCircuitBreaker

        mock_audit.emit = AsyncMock()
        breaker = DefaultCircuitBreaker()

        # Add a policy that always denies
        always_deny = AsyncMock(spec=AIPolicy)
        always_deny.evaluate = AsyncMock(
            return_value=PolicyEvaluation(allowed=False, reason="test-deny", policy_name="TestPolicy")
        )
        breaker.add_policy(always_deny)

        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")
        result = await breaker.evaluate(ctx)

        assert result.allowed is False
        assert breaker._is_tripped is True
        mock_audit.emit.assert_awaited()

    @pytest.mark.asyncio
    @patch("packages.ai_governance.breaker.audit_emitter", new_callable=MagicMock)
    async def test_breaker_blocks_after_trip(self, mock_audit):
        """Once tripped, all subsequent evaluations should be denied immediately."""
        from packages.ai_governance.breaker import DefaultCircuitBreaker

        mock_audit.emit = AsyncMock()
        breaker = DefaultCircuitBreaker()
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")

        # Manually trip the breaker
        await breaker.trip(ctx, "manual-trip")
        assert breaker._is_tripped is True

        # Even with no policies, evaluate should deny
        result = await breaker.evaluate(ctx)
        assert result.allowed is False
        assert "Circuit Breaker is open" in result.reason

    @pytest.mark.asyncio
    @patch("packages.ai_governance.breaker.audit_emitter", new_callable=MagicMock)
    async def test_breaker_reset_allows_again(self, mock_audit):
        """After reset, the breaker should allow evaluations through policies again."""
        from packages.ai_governance.breaker import DefaultCircuitBreaker

        mock_audit.emit = AsyncMock()
        breaker = DefaultCircuitBreaker()
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")

        # Add a policy that always allows
        always_allow = AsyncMock(spec=AIPolicy)
        always_allow.evaluate = AsyncMock(
            return_value=PolicyEvaluation(allowed=True, reason="ok", policy_name="AllowPolicy")
        )
        breaker.add_policy(always_allow)

        # Trip then reset
        await breaker.trip(ctx, "test")
        await breaker.reset(ctx)
        assert breaker._is_tripped is False

        result = await breaker.evaluate(ctx)
        assert result.allowed is True

    @pytest.mark.asyncio
    @patch("packages.ai_governance.breaker.audit_emitter", new_callable=MagicMock)
    async def test_trip_is_idempotent(self, mock_audit):
        """Calling trip multiple times should only emit the audit event once."""
        from packages.ai_governance.breaker import DefaultCircuitBreaker

        mock_audit.emit = AsyncMock()
        breaker = DefaultCircuitBreaker()
        ctx = PolicyContext(user_id="u1", workspace_id="w1", tenant_id="t1")

        await breaker.trip(ctx, "reason-1")
        await breaker.trip(ctx, "reason-2")  # Should be no-op

        # Only one audit emit for the first trip
        assert mock_audit.emit.await_count == 1
