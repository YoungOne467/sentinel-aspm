import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy import select, text
from core.database import AsyncSessionLocal, current_tenant, current_workspace
from packages.audit.models import AuditLogEntry
from packages.audit.emitter import verify_audit_chain, canonical_timestamp

router = APIRouter(prefix="/compliance", tags=["Compliance"])

# Dependency to get session
async def get_session():
    async with AsyncSessionLocal() as session:
        yield session

def redact_payload(payload: dict) -> dict:
    """Recursively redacts sensitive keys from payload."""
    if not payload:
        return {}
    redacted = dict(payload)
    sensitive_keys = {"secret", "key", "token", "password", "password_hash", "pat", "email"}
    for k in list(redacted.keys()):
        if any(sk in k.lower() for sk in sensitive_keys):
            redacted[k] = "[REDACTED]"
        elif isinstance(redacted[k], dict):
            redacted[k] = redact_payload(redacted[k])
    return redacted

@router.get("/export")
async def export_compliance(
    format: str = Query("json", pattern="^(json|csv)$"),
    tenant_id: str = Query("default"),
    workspace_id: str = Query("default"),
    actor: str = Query("system"),
    session = Depends(get_session)
):
    """
    Exports compliance data (audit events, execution history, budget changes, installations, etc.)
    Redacts sensitive details, attributes to the requesting actor/workspace, and includes chain integrity logs for JSON.
    """
    # Force context variables for the current request context
    t_token = current_tenant.set(tenant_id)
    w_token = current_workspace.set(workspace_id)
    
    try:
        # Fetch all audit records for this tenant/workspace
        stmt = select(AuditLogEntry).where(
            AuditLogEntry.tenant_id == tenant_id,
            AuditLogEntry.workspace_id == workspace_id
        ).order_by(AuditLogEntry.created_at.asc(), AuditLogEntry.id.asc())
        
        res = await session.execute(stmt)
        records = res.scalars().all()
        
        # Verify chain integrity
        verification = verify_audit_chain(records)
        
        # Format records for export with redaction
        exported_records = []
        for r in records:
            exported_records.append({
                "id": r.id,
                "event_name": r.event_name,
                "actor": r.actor,
                "payload": redact_payload(r.payload),
                "previous_record_hash": r.previous_record_hash,
                "record_hash": r.record_hash,
                "created_at": canonical_timestamp(r.created_at)
            })
            
        # Segregate into categories for compliance review
        execution_history = [r for r in exported_records if "PluginExecution" in r["event_name"]]
        budget_changes = [r for r in exported_records if "Budget" in r["event_name"]]
        quota_changes = [r for r in exported_records if "Quota" in r["event_name"]]
        installations = [r for r in exported_records if "Installed" in r["event_name"] or "Registry" in r["event_name"]]
        permission_changes = [r for r in exported_records if "Permission" in r["event_name"] or "Capability" in r["event_name"]]
        
        metadata = {
            "exported_at": canonical_timestamp(datetime.now(timezone.utc)),
            "exported_by": actor,
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "verification": verification
        }
        
        if format == "json":
            return JSONResponse(content={
                "metadata": metadata,
                "audit_events": exported_records,
                "execution_history": execution_history,
                "budget_changes": budget_changes,
                "quota_changes": quota_changes,
                "installations": installations,
                "permission_changes": permission_changes
            })
            
        # Return as CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["COMPLIANCE REPORT", "Tenant ID:", tenant_id, "Workspace ID:", workspace_id])
        writer.writerow(["Exported At:", metadata["exported_at"], "Exported By:", actor])
        writer.writerow(["Chain Verification Status:", str(verification["verified"]), "Verification Error:", str(verification["error"])])
        writer.writerow([])
        
        writer.writerow(["ID", "Created At", "Event Name", "Actor", "Payload", "Prev Hash", "Record Hash"])
        for r in exported_records:
            writer.writerow([
                r["id"],
                r["created_at"],
                r["event_name"],
                r["actor"],
                json.dumps(r["payload"]),
                r["previous_record_hash"],
                r["record_hash"]
            ])
            
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=sentinel_compliance_{tenant_id}.csv"}
        )
    finally:
        current_tenant.reset(t_token)
        current_workspace.reset(w_token)
