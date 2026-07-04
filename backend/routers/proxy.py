"""
AETHER Proxy Router — History, Replay & Fuzzer endpoints.

Exposes the RequestStore API for the frontend Proxy view.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from proxy.request_store import store

logger = logging.getLogger("sentinel.routers.proxy")

router = APIRouter()


# ─── Request Schemas ──────────────────────────────────────────────────────────

class ReplayRequest(BaseModel):
    record_id: str
    modifications: Optional[Dict[str, Any]] = None


class FuzzConfig(BaseModel):
    record_id: str
    position_field: str  # e.g. "url", "headers.X-Custom", "body"
    payloads: List[str]
    match_field: Optional[str] = None  # Field to highlight in results


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/api/proxy/history")
async def get_proxy_history(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    host: Optional[str] = Query(None),
):
    """Retrieve paginated proxy history, optionally filtered by host."""
    try:
        records = await asyncio.to_thread(
            store.get_history, limit=limit, offset=offset, host_filter=host
        )
        return records
    except Exception as e:
        logger.error("Failed to retrieve proxy history: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/proxy/history/{record_id}")
async def get_proxy_record(record_id: str):
    """Retrieve the full request/response details for a single proxy record."""
    record = await asyncio.to_thread(store.get_record, record_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Record {record_id} not found")
    return record


@router.post("/api/proxy/replay")
async def replay_request(req: ReplayRequest):
    """Replay a captured request with optional modifications (Repeater)."""
    try:
        result = await store.replay_request(
            record_id=req.record_id,
            modifications=req.modifications,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error("Replay failed for %s: %s", req.record_id, e, exc_info=True)
        raise HTTPException(status_code=502, detail=f"Replay failed: {e}")


@router.post("/api/proxy/fuzz")
async def fuzz_request(config: FuzzConfig):
    """
    Run a parameter fuzzing campaign against a captured request.
    Iterates through the payload list, substituting each payload into the
    designated position field, and returns a results array.
    """
    source_record = await asyncio.to_thread(store.get_record, config.record_id)
    if not source_record:
        raise HTTPException(status_code=404, detail=f"Record {config.record_id} not found")

    results = []
    req = source_record["request"]

    for idx, payload in enumerate(config.payloads):
        modifications: Dict[str, Any] = {}

        # Determine where to inject the payload
        if config.position_field == "url":
            modifications["url"] = payload
        elif config.position_field.startswith("headers."):
            header_name = config.position_field.split(".", 1)[1]
            headers = dict(req.get("headers", {}))
            headers[header_name] = payload
            modifications["headers"] = headers
        elif config.position_field == "body":
            modifications["body_b64"] = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        elif config.position_field == "path":
            # Reconstruct URL with modified path
            original_url = req["url"]
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(original_url)
            new_url = urlunparse(parsed._replace(path=payload))
            modifications["url"] = new_url
        else:
            # Default: treat as URL parameter substitution
            original_url = req["url"]
            if "§" in original_url:
                modifications["url"] = original_url.replace("§", payload, 1)
            else:
                modifications["url"] = payload

        try:
            result = await store.replay_request(
                record_id=config.record_id,
                modifications=modifications,
            )
            results.append({
                "index": idx,
                "payload": payload,
                "status_code": result["response"]["status_code"],
                "response_length": len(base64.b64decode(result["response"]["body_b64"])),
                "response_time": result.get("response_time", 0),
                "record_id": result["id"],
            })
        except Exception as e:
            results.append({
                "index": idx,
                "payload": payload,
                "status_code": 0,
                "response_length": 0,
                "response_time": 0,
                "error": str(e),
            })

    return {
        "total_payloads": len(config.payloads),
        "completed": len([r for r in results if r.get("status_code", 0) > 0]),
        "errors": len([r for r in results if "error" in r]),
        "results": results,
    }
