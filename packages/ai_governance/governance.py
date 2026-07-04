import redis.asyncio as aioredis
import json
import hashlib
import logging
from typing import Tuple, Optional
from packages.audit.emitter import write_compliance_audit

logger = logging.getLogger(__name__)

class BudgetManager:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self._redis_url = redis_url
        self._redis = None

    async def _init_redis(self):
        if self._redis is None:
            self._redis = aioredis.from_url(self._redis_url, decode_responses=True)

    async def get_budget_config(self, tenant_id: str) -> Tuple[float, float, float]:
        """Returns (limit, spent_tokens, spent_infra). Defaults to $100.00 limit if unset."""
        await self._init_redis()
        limit_str = await self._redis.get(f"sentinel:tenant:{tenant_id}:budget:limit")
        limit = float(limit_str) if limit_str is not None else 100.00
        
        spent_tokens_str = await self._redis.get(f"sentinel:tenant:{tenant_id}:budget:spent:tokens")
        spent_tokens = float(spent_tokens_str) if spent_tokens_str is not None else 0.0
        
        spent_infra_str = await self._redis.get(f"sentinel:tenant:{tenant_id}:budget:spent:infra")
        spent_infra = float(spent_infra_str) if spent_infra_str is not None else 0.0
        
        return limit, spent_tokens, spent_infra

    async def update_budget_limit(self, tenant_id: str, new_limit: float, actor: str, session) -> None:
        """Updates a budget limit and emits a compliance audit event."""
        await self._init_redis()
        old_limit, _, _ = await self.get_budget_config(tenant_id)
        await self._redis.set(f"sentinel:tenant:{tenant_id}:budget:limit", str(new_limit))
        
        # Clear warnings triggered
        await self._redis.delete(f"sentinel:tenant:{tenant_id}:budget:warned")
        
        # Emit compliance event
        await write_compliance_audit(
            session=session,
            event_name="BudgetChangedEvent",
            actor=actor,
            tenant_id=tenant_id,
            workspace_id="default",
            payload={
                "tenant_id": tenant_id,
                "old_limit": old_limit,
                "new_limit": new_limit
            }
        )

    async def check_budget_pre_dispatch(self, tenant_id: str, workspace_id: str, projected_tokens: int, projected_infra_cost: float, token_rate: float, session) -> bool:
        """
        Validates projected costs against monthly budget limits before dispatch.
        If limit exceeded, raises ValueError.
        If soft warning threshold reached, logs audit warning.
        """
        await self._init_redis()
        limit, spent_tokens, spent_infra = await self.get_budget_config(tenant_id)
        current_spent = spent_tokens + spent_infra
        
        # Estimate cost
        projected_token_cost = projected_tokens * token_rate
        projected_cost = projected_token_cost + projected_infra_cost
        new_projected_spent = current_spent + projected_cost
        
        # 1. Hard monthly limit breach check (fail closed)
        if new_projected_spent > limit:
            # Emit hard breach event
            await write_compliance_audit(
                session=session,
                event_name="BudgetBreachEvent",
                actor="scheduler",
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                payload={
                    "tenant_id": tenant_id,
                    "workspace_id": workspace_id,
                    "budget_limit": limit,
                    "current_spent": current_spent,
                    "projected_cost": projected_cost,
                    "breach_amount": new_projected_spent - limit
                }
            )
            logger.error(f"Budget hard limit exceeded for tenant {tenant_id}: spent={current_spent}, projected={projected_cost}, limit={limit}")
            raise ValueError(f"Hard budget limit exceeded. Limit: ${limit:.2f}, Projected Total: ${new_projected_spent:.2f}")

        # 2. Soft warning thresholds check (80%, 90%)
        for pct in [0.80, 0.90]:
            threshold_val = limit * pct
            if new_projected_spent >= threshold_val and current_spent < threshold_val:
                warned_key = f"sentinel:tenant:{tenant_id}:budget:warned"
                already_warned = await self._redis.sismember(warned_key, str(pct))
                if not already_warned:
                    await self._redis.sadd(warned_key, str(pct))
                    await write_compliance_audit(
                        session=session,
                        event_name="BudgetWarningEvent",
                        actor="scheduler",
                        tenant_id=tenant_id,
                        workspace_id=workspace_id,
                        payload={
                            "tenant_id": tenant_id,
                            "workspace_id": workspace_id,
                            "budget_limit": limit,
                            "current_spent": current_spent,
                            "projected_cost": projected_cost,
                            "percentage": int(pct * 100)
                        }
                    )
                    logger.warning(f"Budget soft warning threshold ({int(pct*100)}%) reached for tenant {tenant_id}")
                    
        return True

    async def record_actual_usage(self, tenant_id: str, workspace_id: str, execution_id: str, scanner_id: str, actual_tokens: int, actual_infra_cost: float, token_rate: float, session) -> None:
        """Records actual token & infra spent and writes billing usage attribution record."""
        await self._init_redis()
        actual_token_cost = actual_tokens * token_rate
        
        # Increment spent in Redis
        async with self._redis.pipeline() as pipe:
            pipe.incrbyfloat(f"sentinel:tenant:{tenant_id}:budget:spent:tokens", actual_token_cost)
            pipe.incrbyfloat(f"sentinel:tenant:{tenant_id}:budget:spent:infra", actual_infra_cost)
            await pipe.execute()
            
        # Write UsageAttributionRecord to SQL database
        from core.models import UsageAttributionRecord
        record = UsageAttributionRecord(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            execution_id=execution_id,
            scanner_id=scanner_id,
            tokens_consumed=actual_tokens,
            infra_cost=actual_infra_cost,
            token_cost=actual_token_cost
        )
        session.add(record)
        await session.flush()

budget_manager = BudgetManager()
