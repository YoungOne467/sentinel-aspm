from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from core.database import AsyncSessionLocal
from core.schemas import TargetCreate, TargetUpdate
from services.scanner import (
    list_targets_service,
    create_target_service,
    get_target_service,
    update_target_service,
    delete_target_service,
    get_topology_service,
    get_target_routes_service,
    get_target_ai_triage_service,
    get_target_logic_map_service,
    list_dlp_findings_service,
    list_discovered_parameters_service,
)

logger = logging.getLogger("sentinel.routers.targets")
router = APIRouter()

@router.get("/api/targets")
async def list_targets():
    async with AsyncSessionLocal() as session:
        return await list_targets_service(session)

@router.post("/api/targets", status_code=201)
async def create_target(req: TargetCreate):
    async with AsyncSessionLocal() as session:
        return await create_target_service(req, session)

@router.get("/api/targets/{target_id}")
async def get_target(target_id: str):
    async with AsyncSessionLocal() as session:
        res = await get_target_service(target_id, session)
        if not res:
            raise HTTPException(status_code=404, detail="Target not found")
        return res

@router.put("/api/targets/{target_id}")
async def update_target(target_id: str, req: TargetUpdate):
    async with AsyncSessionLocal() as session:
        return await update_target_service(target_id, req, session)

@router.delete("/api/targets/{target_id}")
async def delete_target(target_id: str):
    async with AsyncSessionLocal() as session:
        return await delete_target_service(target_id, session)

@router.get("/api/topology")
async def get_topology(target_id: str = Query(...)):
    async with AsyncSessionLocal() as session:
        return await get_topology_service(target_id, session)

@router.get("/api/targets/{target_id}/routes")
async def get_target_routes(target_id: str):
    async with AsyncSessionLocal() as session:
        return await get_target_routes_service(target_id, session)

@router.get("/api/targets/{target_id}/triage")
async def get_target_ai_triage(target_id: str):
    async with AsyncSessionLocal() as session:
        return await get_target_ai_triage_service(target_id, session)

@router.get("/api/targets/{target_id}/logic-map")
async def get_target_logic_map(target_id: str):
    async with AsyncSessionLocal() as session:
        return await get_target_logic_map_service(target_id, session)

@router.get("/api/targets/{target_id}/dlp")
async def list_dlp_findings(target_id: str):
    async with AsyncSessionLocal() as session:
        return await list_dlp_findings_service(target_id, session)

@router.get("/api/targets/{target_id}/parameters")
async def list_discovered_parameters(target_id: str):
    async with AsyncSessionLocal() as session:
        return await list_discovered_parameters_service(target_id, session)
