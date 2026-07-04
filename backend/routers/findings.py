from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter

from core.database import AsyncSessionLocal
from core.schemas import FindingUpdate
from services.scanner import (
    list_findings_service,
    update_finding_service,
    get_findings_stats_service,
)

logger = logging.getLogger("sentinel.routers.findings")
router = APIRouter()

@router.get("/api/findings")
async def list_findings(
    target_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "first_seen",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 25,
):
    async with AsyncSessionLocal() as session:
        return await list_findings_service(
            target_id, severity, status, category, search,
            sort_by, sort_order, page, page_size, session
        )

@router.put("/api/findings/{finding_id}")
async def update_finding(finding_id: str, req: FindingUpdate):
    async with AsyncSessionLocal() as session:
        return await update_finding_service(finding_id, req, session)

@router.get("/api/findings/stats")
async def findings_stats(target_id: Optional[str] = None):
    async with AsyncSessionLocal() as session:
        return await get_findings_stats_service(target_id, session)
