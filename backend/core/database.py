import os
import asyncio
import logging
import json
from datetime import datetime
from typing import List, Any, Dict
from contextvars import ContextVar
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker, AsyncEngine
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy import create_engine, inspect, text, event
from sqlalchemy.dialects.postgresql import insert as pg_insert

logger = logging.getLogger(__name__)

DEFAULT_DB_URL = "postgresql+asyncpg://user:password@localhost:5432/db"
DATABASE_URL = os.environ.get("DATABASE_URL", DEFAULT_DB_URL)
SYNC_DATABASE_URL = os.environ.get(
    "SYNC_DATABASE_URL",
    DATABASE_URL.replace("+asyncpg", "")
)
EMERGENCY_DUMP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "emergency_dump.json")

# Context variables for RLS
current_tenant: ContextVar[str] = ContextVar("current_tenant", default="default")
current_workspace: ContextVar[str] = ContextVar("current_workspace", default="default")

kwargs = {
    "echo": False,
    "pool_pre_ping": True,
}
if "postgresql" in DATABASE_URL:
    kwargs["pool_size"] = 20
    kwargs["max_overflow"] = 10

engine = create_async_engine(
    DATABASE_URL,
    **kwargs
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

@event.listens_for(Session, 'after_begin')
def set_pg_context(session, transaction, connection):
    if connection.dialect.name == "postgresql":
        tenant = current_tenant.get() or ""
        workspace = current_workspace.get() or ""
        connection.execute(text("SELECT set_config('sentinel.current_tenant', :t, true)"), {"t": tenant})
        connection.execute(text("SELECT set_config('sentinel.current_workspace', :w, true)"), {"w": workspace})

class Base(DeclarativeBase):
    pass


class PostgresWriter:
    """
    Direct writer for PostgreSQL replacing MicroBatchWriter.
    Writes immediately since Postgres handles concurrency.
    """
    async def start(self):
        pass

    async def stop(self):
        pass

    async def _dump_to_emergency_file(self, item: Any):
        try:
            serialized = {}
            if hasattr(item, "__table__"):
                for c in item.__table__.columns:
                    val = getattr(item, c.name)
                    if isinstance(val, datetime):
                        serialized[c.name] = val.isoformat()
                    else:
                        serialized[c.name] = val
            elif hasattr(item, "__dict__"):
                serialized = dict(item.__dict__)
                serialized.pop('_sa_instance_state', None)
                for k, v in serialized.items():
                    if isinstance(v, datetime):
                        serialized[k] = v.isoformat()
            else:
                serialized = {"raw": repr(item)}

            def write_line():
                with open(EMERGENCY_DUMP_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps(serialized, default=str) + "\n")

            await asyncio.to_thread(write_line)
        except Exception as e:
            logger.error("Failed to dump item to emergency file: %s", e)

    async def enqueue(self, item: Any):
        tenant = getattr(item, "tenant_id", None) or "default"
        workspace = getattr(item, "workspace_id", None) or "default"
        if hasattr(item, "tenant_id") and getattr(item, "tenant_id") is None:
            item.tenant_id = tenant
        if hasattr(item, "workspace_id") and getattr(item, "workspace_id") is None:
            item.workspace_id = workspace

        token_t = current_tenant.set(tenant)
        token_w = current_workspace.set(workspace)
        try:
            async with AsyncSessionLocal() as session:
                try:
                    # Handle Findings with Postgres ON CONFLICT DO NOTHING
                    if hasattr(item, '__tablename__') and item.__tablename__ == 'findings':
                        from core.models import Finding
                        row = {}
                        for c in Finding.__table__.columns:
                            val = getattr(item, c.name, None)
                            if val is not None or not c.nullable:
                                row[c.name] = val
                        stmt = pg_insert(Finding).values(row)
                        stmt = stmt.on_conflict_do_nothing(index_elements=['hash'])
                        await session.execute(stmt)
                    else:
                        session.add(item)
                    await session.commit()
                except Exception as e:
                    logger.error("Error inserting item %s: %s", type(item).__name__, e)
                    await session.rollback()
                    await self._dump_to_emergency_file(item)
        finally:
            current_tenant.reset(token_t)
            current_workspace.reset(token_w)

    async def enqueue_many(self, items: List[Any]):
        for item in items:
            await self.enqueue(item)

    async def flush(self):
        pass

batch_writer = PostgresWriter()

def _ensure_column(sync_engine, table_name: str, column_name: str, ddl: str) -> None:
    inspector = inspect(sync_engine)
    if table_name not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name in existing:
        return
    with sync_engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {ddl}"))

def _ensure_index(sync_engine, index_name: str, table_name: str, columns: str) -> None:
    inspector = inspect(sync_engine)
    if table_name not in inspector.get_table_names():
        return
    existing_indexes = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name in existing_indexes:
        return
    with sync_engine.begin() as conn:
        conn.execute(text(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns})"))

def init_db():
    sync_engine = create_engine(SYNC_DATABASE_URL)
    try:
        from core.models import Base
        import packages.audit.models
        Base.metadata.create_all(bind=sync_engine)
        
        # Performance indexes for large sets
        _ensure_index(sync_engine, "ix_findings_category", "findings", "category")
        _ensure_index(sync_engine, "ix_findings_first_seen", "findings", "first_seen")
        _ensure_index(sync_engine, "ix_findings_severity", "findings", "severity")
        _ensure_index(sync_engine, "ix_findings_status", "findings", "status")
        _ensure_index(sync_engine, "ix_findings_target_id", "findings", "target_id")

        # RLS bootstrapping for PostgreSQL
        if sync_engine.dialect.name == "postgresql":
            try:
                with sync_engine.begin() as conn:
                    # 1. Create get_current_tenant() and get_current_workspace() functions
                    conn.execute(text("""
                    CREATE OR REPLACE FUNCTION get_current_tenant() RETURNS text AS $$
                    DECLARE
                      t text;
                    BEGIN
                      t := current_setting('sentinel.current_tenant', true);
                      IF t IS NULL OR t = '' THEN
                        RAISE EXCEPTION 'Missing tenant context';
                      END IF;
                      RETURN t;
                    END;
                    $$ LANGUAGE plpgsql;
                    """))
                    
                    conn.execute(text("""
                    CREATE OR REPLACE FUNCTION get_current_workspace() RETURNS text AS $$
                    DECLARE
                      w text;
                    BEGIN
                      w := current_setting('sentinel.current_workspace', true);
                      IF w IS NULL OR w = '' THEN
                        RAISE EXCEPTION 'Missing workspace context';
                      END IF;
                      RETURN w;
                    END;
                    $$ LANGUAGE plpgsql;
                    """))
                    
                    # 2. Create sentinel_admin role if not exists
                    role_exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_admin'")).scalar()
                    if not role_exists:
                        conn.execute(text("CREATE ROLE sentinel_admin"))
                    
                    # 3. Enable RLS on all tenant-scoped tables
                    tables_with_rls = [
                        "targets", "jobs", "findings", "js_findings", "crawled_urls",
                        "discovered_subdomains", "dlp_findings", "shadow_apis", "discovered_parameters",
                        "vulnerabilities", "OOB_Canaries", "websocket_streams",
                        "workspace_capability_approvals", "usage_attribution_records", "audit_log_entries"
                    ]
                    for table in tables_with_rls:
                        conn.execute(text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
                        conn.execute(text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
                        
                        conn.execute(text(f'DROP POLICY IF EXISTS tenant_isolation_policy ON "{table}"'))
                        conn.execute(text(f'CREATE POLICY tenant_isolation_policy ON "{table}" FOR ALL USING ( '
                                          f"  pg_has_role(current_user, 'sentinel_admin', 'member') "
                                          f"  OR (tenant_id = get_current_tenant() AND workspace_id = get_current_workspace()) "
                                          f") WITH CHECK ( "
                                          f"  pg_has_role(current_user, 'sentinel_admin', 'member') "
                                          f"  OR (tenant_id = get_current_tenant() AND workspace_id = get_current_workspace()) "
                                          f")"))
            except Exception as rls_err:
                logger.warning("Failed to initialize database RLS/policies: %s", rls_err)

        try:
            with sync_engine.begin() as conn:
                res = conn.execute(text("SELECT COUNT(*) FROM platform_settings")).scalar()
                if res == 0:
                    conn.execute(text(
                        "INSERT INTO platform_settings (id, max_concurrent_workers, rate_limit_rps, global_blacklist, ai_routing_config) "
                        "VALUES ('default', 5, 10, '', '{}')"
                    ))
        except Exception as se_err:
            logger.warning("Failed to initialize default platform settings: %s", se_err)
    finally:
        sync_engine.dispose()
    print("Database schema ready.")
