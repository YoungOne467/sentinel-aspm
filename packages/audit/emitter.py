import logging
from datetime import datetime, timezone
import uuid
import hashlib
import json
from sqlalchemy import text

from .interfaces import AuditEmitter, AuditEvent
from packages.events.envelope import EventEnvelope
from packages.events.redis_bus import RedisStreamEventBus
from packages.observability.telemetry import get_trace_context_payload
from packages.observability.slo import audit_publish_hist, SLOMonitor
from packages.audit.models import AuditLogEntry

logger = logging.getLogger(__name__)

# Initialize default EventBus for auditing transit (RedisStreamEventBus as default OSS adapter)
event_bus = RedisStreamEventBus()

def canonical_timestamp(dt: datetime) -> str:
    """Always formats a datetime to UTC string with microsecond precision and Z suffix."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

async def write_compliance_audit(session, event_name: str, actor: str, tenant_id: str, workspace_id: str, payload: dict) -> AuditLogEntry:
    """
    Writes a compliance audit log entry directly to the database.
    Performs PostgreSQL advisory locking to serialize writes per tenant/workspace.
    Raises exception on failure to fail closed.
    """
    try:
        # 1. Advisory Lock per Tenant & Workspace
        lock_str = f"{tenant_id}:{workspace_id}"
        lock_id = int(hashlib.sha256(lock_str.encode("utf-8")).hexdigest()[:8], 16)
        
        bind = session.bind
        is_postgres = bind.dialect.name == "postgresql" if bind else False
        
        if is_postgres:
            await session.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id})
            
        # 2. Get last record's hash
        query = text("""
            SELECT record_hash FROM audit_log_entries 
            WHERE tenant_id = :t AND workspace_id = :w 
            ORDER BY created_at DESC, id DESC LIMIT 1
        """)
        res = await session.execute(query, {"t": tenant_id, "w": workspace_id})
        row = res.fetchone()
        previous_hash = row[0] if row else "0" * 64
        
        # 3. Compute canonical hash
        created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        created_at_str = canonical_timestamp(created_at)
        payload_str = json.dumps(payload, sort_keys=True)
        
        hash_payload = f"{event_name}|{actor}|{payload_str}|{created_at_str}|{tenant_id}|{workspace_id}|{previous_hash}"
        record_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
        
        # 4. Insert Audit Log
        entry = AuditLogEntry(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            event_name=event_name,
            actor=actor,
            payload=payload,
            previous_record_hash=previous_hash,
            record_hash=record_hash,
            created_at=created_at
        )
        session.add(entry)
        await session.flush()
        logger.info(f"Compliance audit record written. Event: {event_name}, Hash: {record_hash}")
        return entry
    except Exception as e:
        logger.critical(f"Compliance audit write failed: {e}. Failing closed.")
        raise RuntimeError(f"Audit write failed: {e}")

def verify_audit_chain(records) -> dict:
    """
    Verifies the cryptographic integrity of a list of audit records.
    Returns a dict summarizing validation results.
    """
    if not records:
        return {"verified": True, "error": None, "count": 0}
        
    chains = {}
    for r in records:
        key = (r.tenant_id, r.workspace_id)
        if key not in chains:
            chains[key] = []
        chains[key].append(r)
        
    for key, chain_records in chains.items():
        chain_records.sort(key=lambda r: (r.created_at, r.id))
        expected_prev_hash = "0" * 64
        
        for r in chain_records:
            if r.previous_record_hash != expected_prev_hash:
                return {
                    "verified": False,
                    "error": f"Chain broken at record {r.id}: expected previous hash {expected_prev_hash}, got {r.previous_record_hash}",
                    "count": len(records)
                }
                
            created_at_str = canonical_timestamp(r.created_at)
            payload_str = json.dumps(r.payload, sort_keys=True)
            
            hash_payload = f"{r.event_name}|{r.actor}|{payload_str}|{created_at_str}|{r.tenant_id}|{r.workspace_id}|{r.previous_record_hash}"
            computed_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
            
            if r.record_hash != computed_hash:
                return {
                    "verified": False,
                    "error": f"Tampering detected at record {r.id}: computed hash {computed_hash} does not match stored hash {r.record_hash}",
                    "count": len(records)
                }
                
            expected_prev_hash = r.record_hash
            
    return {"verified": True, "error": None, "count": len(records)}

class EventBusAuditEmitter(AuditEmitter):
    """Event Bus-driven Audit Emitter publishing standardized, immutable envelopes asynchronously."""

    async def emit(self, event: AuditEvent, actor: str) -> None:
        # Measure SLO Target: p95 event publication < 100ms
        with SLOMonitor(audit_publish_hist, {"action": "publish_audit"}):
            try:
                # Resolve OTel trace correlation metadata dynamically
                trace_ctx = get_trace_context_payload()
                trace_id = trace_ctx.get("trace_id", "")
                
                # Retrieve tenant context if present in payload, default to 'default'
                tenant_id = event.payload.get("tenant_id", "default")
                
                # Standardized envelope fields
                envelope = EventEnvelope(
                    event_id=str(uuid.uuid4()),
                    event_type=event.name,
                    trace_id=trace_id,
                    correlation_id=trace_id,  # Map correlation to trace ID by default
                    tenant_id=tenant_id,
                    timestamp=datetime.utcnow(),
                    schema_version="1.0",
                    source_context="sentinel-audit",
                    payload={
                        "actor": actor,
                        "event_data": event.payload
                    }
                )

                # Publish to event bus topic 'sentinel_audit_logs'
                await event_bus.publish("sentinel_audit_logs", envelope)
                logger.debug(f"Audit event {event.name} successfully published to EventBus.")
            except Exception as e:
                # Fail-safe local log to protect caller from message broker failures
                logger.critical(f"Failed to publish async audit event {event.name} to EventBus: {e}")

# Global audit emitter instance
audit_emitter = EventBusAuditEmitter()
