from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException

from core.database import AsyncSessionLocal
from core.orchestrator import orchestrator
from core.schemas import JobCreate
from services.scanner import (
    list_jobs_service,
    create_job_service,
    get_job_service,
)

logger = logging.getLogger("sentinel.routers.jobs")
router = APIRouter()

@router.get("/api/jobs")
async def list_jobs(
    target_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
):
    async with AsyncSessionLocal() as session:
        return await list_jobs_service(target_id, status, limit, session)

@router.post("/api/jobs", status_code=201)
async def create_job(req: JobCreate):
    async with AsyncSessionLocal() as session:
        return await create_job_service(req, session)

@router.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    async with AsyncSessionLocal() as session:
        return await get_job_service(job_id, session)

@router.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    cancelled = await orchestrator.cancel_job(job_id)
    if cancelled:
        return {"status": "cancelled"}
    raise HTTPException(status_code=404, detail="Job not found or already completed")
