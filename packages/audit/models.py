import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, JSON, DateTime, Index
from core.database import Base

def gen_id() -> str:
    return str(uuid.uuid4())

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

class AuditLogEntry(Base):
    __tablename__ = "audit_log_entries"

    id = Column(String, primary_key=True, default=gen_id)
    tenant_id = Column(String, nullable=False, default="default", server_default="default", index=True)
    workspace_id = Column(String, nullable=False, default="default", server_default="default", index=True)
    event_name = Column(String, nullable=False, index=True)
    actor = Column(String, nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    previous_record_hash = Column(String, nullable=True)
    record_hash = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=now_utc, index=True)

    __table_args__ = (
        Index("ix_audit_log_entries_name_time", "event_name", "created_at"),
        Index("ix_audit_log_entries_tenant_workspace", "tenant_id", "workspace_id"),
    )
