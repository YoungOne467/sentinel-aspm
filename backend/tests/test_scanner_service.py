import pytest
from core.database import AsyncSessionLocal
from core.models import Finding, Target, gen_id
from core.schemas import FindingUpdate
from services.scanner import update_finding_service
from fastapi import HTTPException
from datetime import datetime, timedelta, timezone

@pytest.mark.asyncio
async def test_update_finding_service_not_found():
    async with AsyncSessionLocal() as session:
        req = FindingUpdate(status="confirmed")
        with pytest.raises(HTTPException) as exc_info:
            await update_finding_service("nonexistent-id", req, session)
        assert exc_info.value.status_code == 404

@pytest.mark.asyncio
async def test_update_finding_service_success():
    async with AsyncSessionLocal() as session:
        # Set up a target first
        target = Target(
            id=gen_id(),
            name="Test Target",
            host="example.com"
        )
        session.add(target)
        await session.flush()

        # Set up a finding
        finding = Finding(
            id=gen_id(),
            target_id=target.id,
            title="Test Finding",
            severity="high",
            status="open",
            hash="test-hash-1"
        )
        session.add(finding)
        await session.commit()

        # Update finding
        req = FindingUpdate(status="confirmed")
        result = await update_finding_service(finding.id, req, session)
        assert result == {"status": "updated"}

        # Verify update
        updated_finding = await session.get(Finding, finding.id)
        assert updated_finding.status == "confirmed"

@pytest.mark.asyncio
async def test_update_finding_service_empty_update():
    async with AsyncSessionLocal() as session:
        # Set up a target first
        target = Target(
            id=gen_id(),
            name="Test Target 2",
            host="example2.com"
        )
        session.add(target)
        await session.flush()

        # Set up a finding
        initial_timestamp = datetime.now(timezone.utc) - timedelta(days=1)
        finding = Finding(
            id=gen_id(),
            target_id=target.id,
            title="Test Finding Empty Update",
            severity="low",
            status="open",
            hash="test-hash-2"
        )
        finding.created_at = initial_timestamp
        finding.updated_at = initial_timestamp
        session.add(finding)
        await session.commit()

        # Reload to ensure timestamps are set
        finding_id = finding.id
        session.expunge(finding)
        reloaded_finding = await session.get(Finding, finding_id)
        assert reloaded_finding.status == "open"

        # Update finding with empty request
        req = FindingUpdate() # Empty update, no status
        result = await update_finding_service(finding_id, req, session)
        assert result == {"status": "updated"}

        # Verify no change and no failure
        final_finding = await session.get(Finding, finding_id)
        assert final_finding.status == "open"
