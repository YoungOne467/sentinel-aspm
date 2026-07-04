import os
import pytest
import asyncio
import hashlib
import json
from datetime import datetime, timezone
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from core.database import AsyncSessionLocal, current_tenant, current_workspace, init_db
from core.models import Base, Target, UsageAttributionRecord, WorkspaceCapabilityApproval
from packages.audit.models import AuditLogEntry
from packages.audit.emitter import write_compliance_audit, verify_audit_chain
from packages.ai_governance.governance import budget_manager
from packages.plugin_sdk.resolver import capability_resolver
from packages.plugin_sdk.registry import PluginRegistry, SignatureVerifier, TrustLevel
from packages.execution.interfaces import ExecutionContract
from packages.execution.fleet import FleetRegistry
from packages.execution.quotas import InMemoryTenantQuotaStore
from packages.execution.scheduler import FleetScheduler

pytestmark = pytest.mark.asyncio(loop_scope="module")

# Test Ed25519 Key Pair
from cryptography.hazmat.primitives.asymmetric import ed25519

class MockRedis:
    def __init__(self):
        self.data = {}
        self.sets = {}

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, value):
        self.data[key] = str(value)
        return True

    async def delete(self, *keys):
        for key in keys:
            self.data.pop(key, None)
            self.sets.pop(key, None)
        return len(keys)

    async def sadd(self, key, *values):
        if key not in self.sets:
            self.sets[key] = set()
        count = 0
        for val in values:
            if str(val) not in self.sets[key]:
                self.sets[key].add(str(val))
                count += 1
        return count

    async def srem(self, key, *values):
        if key not in self.sets:
            return 0
        count = 0
        for val in values:
            if str(val) in self.sets[key]:
                self.sets[key].remove(str(val))
                count += 1
        return count

    async def sismember(self, key, value):
        if key not in self.sets:
            return False
        return str(value) in self.sets[key]

    async def incrbyfloat(self, key, amount):
        val = float(self.data.get(key, 0.0))
        val += amount
        self.data[key] = str(val)
        return val

    def pipeline(self):
        return MockPipeline(self)

class MockPipeline:
    def __init__(self, mock_redis):
        self.mock_redis = mock_redis
        self.cmds = []

    def incrbyfloat(self, key, amount):
        self.cmds.append(("incrbyfloat", key, amount))
        return self

    async def execute(self):
        res = []
        for cmd, *args in self.cmds:
            if cmd == "incrbyfloat":
                res.append(await self.mock_redis.incrbyfloat(*args))
        return res

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="module")
def ed_keys():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()
    from sqlalchemy import create_engine
    from core.database import SYNC_DATABASE_URL
    sync_engine = create_engine(SYNC_DATABASE_URL)
    with sync_engine.begin() as conn:
        if sync_engine.dialect.name == "postgresql":
            role_exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_test_role'")).scalar()
            if not role_exists:
                conn.execute(text("CREATE ROLE sentinel_test_role WITH LOGIN PASSWORD 'sentinel_test_password'"))
            conn.execute(text("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sentinel_test_role"))
            conn.execute(text("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sentinel_test_role"))
            conn.execute(text("GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO sentinel_test_role"))
    sync_engine.dispose()
    yield

@pytest.fixture(scope="module", autouse=True)
def mock_redis_fixture():
    import redis.asyncio as aioredis
    from packages.ai_governance.governance import budget_manager
    
    mock_client = MockRedis()
    original_from_url = aioredis.from_url
    aioredis.from_url = lambda *args, **kwargs: mock_client
    budget_manager._redis = mock_client
    
    yield mock_client
    
    aioredis.from_url = original_from_url
    budget_manager._redis = None

@pytest.mark.asyncio(loop_scope="module")
class TestPhase10Governance:

    # 1. Immutable Audit Chain Validation & Tamper Detection
    async def test_audit_chain_integrity_and_tampering(self):
        async with AsyncSessionLocal() as session:
            await session.execute(text("DELETE FROM audit_log_entries"))
            await session.commit()
            
        async with AsyncSessionLocal() as session:
            await write_compliance_audit(session, "PermissionChangedEvent", "admin", "acme", "ws-1", {"role": "reader"})
            await write_compliance_audit(session, "BudgetChangedEvent", "admin", "acme", "ws-1", {"limit": 500})
            await write_compliance_audit(session, "ScannerInstalledEvent", "admin", "acme", "ws-1", {"scanner": "vuln-scanner"})
            await session.commit()
            
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(AuditLogEntry).where(AuditLogEntry.tenant_id == "acme").order_by(AuditLogEntry.created_at.asc(), AuditLogEntry.id.asc()))
            records = res.scalars().all()
            assert len(records) == 3
            
            res_verify = verify_audit_chain(records)
            assert res_verify["verified"] is True
            assert res_verify["error"] is None
            
            # Tamper with the middle record's payload
            records[1].payload = {"limit": 9999}
            
            res_verify_tampered = verify_audit_chain(records)
            assert res_verify_tampered["verified"] is False
            assert "Tampering detected" in res_verify_tampered["error"]

    # 2. Database RLS context validation
    async def test_rls_default_deny_and_missing_context(self):
        async with AsyncSessionLocal() as session:
            bind = session.bind
            if bind.dialect.name != "postgresql":
                pytest.skip("RLS tests require PostgreSQL engine")
                
        current_tenant.set("")
        current_workspace.set("")
        
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(text("SET LOCAL ROLE sentinel_test_role"))
                with pytest.raises(Exception) as exc:
                    await session.execute(select(Target))
                assert "Missing tenant context" in str(exc.value)

    # 3. RLS Isolation Enforcement
    async def test_rls_isolation_enforcement(self):
        async with AsyncSessionLocal() as session:
            bind = session.bind
            if bind.dialect.name != "postgresql":
                pytest.skip("RLS tests require PostgreSQL engine")
                
            current_tenant.set("admin-setup")
            current_workspace.set("admin-ws")
            await session.execute(text("DELETE FROM targets"))
            await session.commit()
            
        current_tenant.set("tenant-a")
        current_workspace.set("ws-a")
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(text("SET LOCAL ROLE sentinel_test_role"))
                t1 = Target(name="Target A", host="127.0.0.1", tenant_id="tenant-a", workspace_id="ws-a")
                session.add(t1)
            
        current_tenant.set("tenant-b")
        current_workspace.set("ws-b")
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(text("SET LOCAL ROLE sentinel_test_role"))
                t2 = Target(name="Target B", host="127.0.0.1", tenant_id="tenant-b", workspace_id="ws-b")
                session.add(t2)
            
        current_tenant.set("tenant-a")
        current_workspace.set("ws-a")
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(text("SET LOCAL ROLE sentinel_test_role"))
                res = await session.execute(select(Target))
                targets = res.scalars().all()
                assert len(targets) == 1
                assert targets[0].name == "Target A"

    # 4. Hard-limit Budget Rejection
    async def test_hard_limit_budget_rejection(self):
        tenant = "budget-test-tenant"
        await budget_manager._init_redis()
        await budget_manager._redis.set(f"sentinel:tenant:{tenant}:budget:limit", "1.00")
        await budget_manager._redis.delete(f"sentinel:tenant:{tenant}:budget:spent:tokens")
        await budget_manager._redis.delete(f"sentinel:tenant:{tenant}:budget:spent:infra")
        
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        scheduler = FleetScheduler(
            registry=registry,
            quota_store=quota_store,
            budget_manager=budget_manager,
            session_factory=AsyncSessionLocal,
            token_rate=0.0001
        )
        
        contract = ExecutionContract(
            contract_id="c1",
            execution_id="e1",
            tenant_id=tenant,
            workspace_id="default",
            contract_version="1.0.0",
            target_node_id="node1",
            scheduler_id="scheduler-active",
            scheduler_version="1.0.0",
            timestamp=0.0,
            expires_at=0.0,
            nonce="n1",
            signature="s1",
            image="img1",
            command=[],
            env={"PROJECTED_TOKENS": "50000", "PROJECTED_INFRA_COST": "0.10"},
            capabilities=[]
        )
        
        with pytest.raises(ValueError) as exc:
            await scheduler.schedule(contract)
        assert "Hard budget limit exceeded" in str(exc.value)

    # 5. Soft-limit Warning Emission
    async def test_soft_limit_warning_emission(self):
        tenant = "warning-test-tenant"
        await budget_manager._init_redis()
        await budget_manager._redis.set(f"sentinel:tenant:{tenant}:budget:limit", "10.00")
        await budget_manager._redis.delete(f"sentinel:tenant:{tenant}:budget:spent:tokens")
        await budget_manager._redis.delete(f"sentinel:tenant:{tenant}:budget:spent:infra")
        await budget_manager._redis.delete(f"sentinel:tenant:{tenant}:budget:warned")
        
        async with AsyncSessionLocal() as session:
            await session.execute(text("DELETE FROM audit_log_entries WHERE tenant_id = :t"), {"t": tenant})
            await session.commit()
            
        registry = FleetRegistry()
        quota_store = InMemoryTenantQuotaStore()
        scheduler = FleetScheduler(
            registry=registry,
            quota_store=quota_store,
            budget_manager=budget_manager,
            session_factory=AsyncSessionLocal,
            token_rate=0.0001
        )
        
        from packages.execution.fleet import RuntimeNode
        node = RuntimeNode(
            node_id="node1", tenant_scope=tenant, runtime_types=["standard"],
            total_memory=1000, total_cpu=2.0
        )
        registry.register_node(node)
        
        contract = ExecutionContract(
            contract_id="c1",
            execution_id="e1",
            tenant_id=tenant,
            workspace_id="default",
            contract_version="1.0.0",
            target_node_id="node1",
            scheduler_id="scheduler-active",
            scheduler_version="1.0.0",
            timestamp=0.0,
            expires_at=0.0,
            nonce="n1",
            signature="s1",
            image="img1",
            command=[],
            env={"PROJECTED_TOKENS": "85000", "PROJECTED_INFRA_COST": "0.10"},
            capabilities=[]
        )
        
        await scheduler.schedule(contract)
        
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(AuditLogEntry).where(
                AuditLogEntry.tenant_id == tenant,
                AuditLogEntry.event_name == "BudgetWarningEvent"
            ))
            warnings = res.scalars().all()
            assert len(warnings) == 1
            assert warnings[0].payload["percentage"] == 80

    # 6. Signed Registry Entry Acceptance
    # 7. Unsigned Registry Entry Rejection
    async def test_signed_and_unsigned_registry_acceptance(self, ed_keys):
        priv_key, pub_key = ed_keys
        pub_key_hex = pub_key.public_bytes_raw().hex()
        
        registry = PluginRegistry()
        registry.verifier.trust_roots["verified-test-publisher"] = pub_key_hex
        
        manifest = {
            "id": "scanner-test",
            "name": "Signed Scanner",
            "version": "1.0.0",
            "runtime": {"image": "alpine:latest"},
            "entrypoint": ["echo", "hello"],
            "capabilities": ["filesystem:read"],
            "secrets": []
        }
        
        is_trusted_unsigned = await registry.evaluate_trust(manifest, None)
        assert is_trusted_unsigned is False
        
        payload = registry.verifier.canonicalize_manifest_payload(manifest)
        sig_bytes = priv_key.sign(payload)
        
        signature_block = {
            "signature_bytes": sig_bytes.hex(),
            "trust_level": "Verified",
            "provenance": {
                "publisher": {
                    "id": "test-pub",
                    "signing_key": "verified-test-publisher"
                },
                "source": {
                    "repository": "git://github.com",
                    "commit": "abc"
                },
                "build": {
                    "image_digest": "alpine:latest"
                }
            }
        }
        
        is_trusted_signed = await registry.evaluate_trust(manifest, signature_block)
        assert is_trusted_signed is True

    # 8. Capability Approval Enforcement
    async def test_capability_approval_enforcement(self):
        plugin_id = "test-nmap"
        
        async with AsyncSessionLocal() as session:
            await session.execute(text("DELETE FROM workspace_capability_approvals WHERE plugin_id = :p"), {"p": plugin_id})
            await session.commit()
            
        sig_block = {
            "signature_bytes": "VALID_OFFICIAL_SIG",
            "trust_level": "Official",
            "provenance": {
                "publisher": {
                    "id": "official-pub",
                    "signing_key": "official-sentinel-fingerprint"
                },
                "source": {
                    "repository": "git://github.com/sentinel",
                    "commit": "123"
                },
                "build": {
                    "image_digest": "official-digest"
                }
            }
        }
            
        res_decision = await capability_resolver.validate(
            requested_capabilities=["network:external"],
            plugin_id=plugin_id,
            manifest_data={"id": plugin_id, "capabilities": ["network:external"], "runtime": {"image": "official-digest"}},
            signature_block=sig_block
        )
        assert res_decision.allowed is False
        assert "network:external" in res_decision.denied_capabilities
        
        current_workspace.set("default")
        async with AsyncSessionLocal() as session:
            app = WorkspaceCapabilityApproval(
                workspace_id="default",
                plugin_id=plugin_id,
                capability="network:external",
                approved_by="admin"
            )
            session.add(app)
            await session.commit()
            
        res_decision_approved = await capability_resolver.validate(
            requested_capabilities=["network:external"],
            plugin_id=plugin_id,
            manifest_data={"id": plugin_id, "capabilities": ["network:external"], "runtime": {"image": "official-digest"}},
            signature_block=sig_block
        )
        assert res_decision_approved.allowed is True

    # 9. Denylist Rejection
    async def test_denylist_rejection(self):
        plugin_id = "blocked-scanner"
        registry = PluginRegistry()
        await budget_manager._init_redis()
        
        await budget_manager._redis.sadd("sentinel:registry:denylist", plugin_id.lower())
        
        try:
            is_trusted = await registry.evaluate_trust(
                manifest_data={"id": plugin_id, "capabilities": []},
                signature_block={"signature_bytes": "VALID_OFFICIAL_SIG", "trust_level": "Official", "provenance": {"publisher": {"signing_key": "official-sentinel-fingerprint"}}}
            )
            assert is_trusted is False
        finally:
            await budget_manager._redis.srem("sentinel:registry:denylist", plugin_id.lower())

    # 10. Compliance Export Verification Metadata
    async def test_compliance_export_verification_metadata(self):
        from backend.routers.compliance import export_compliance
        
        async with AsyncSessionLocal() as session:
            await session.execute(text("DELETE FROM audit_log_entries"))
            await session.commit()
            
        async with AsyncSessionLocal() as session:
            await write_compliance_audit(session, "QuotaChangedEvent", "admin", "default", "default", {"quota": 100})
            await session.commit()
            
        async with AsyncSessionLocal() as session:
            response = await export_compliance(
                format="json",
                tenant_id="default",
                workspace_id="default",
                actor="test-compliance-actor",
                session=session
            )
            
            data = json.loads(response.body)
            assert "metadata" in data
            assert data["metadata"]["exported_by"] == "test-compliance-actor"
            assert "verification" in data["metadata"]
            assert data["metadata"]["verification"]["verified"] is True
            assert len(data["audit_events"]) == 1
