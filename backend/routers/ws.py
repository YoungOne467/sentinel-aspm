from __future__ import annotations

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("sentinel.routers.ws")
router = APIRouter()

_ws_manager = None

def init_ws_router(ws_manager):
    global _ws_manager
    _ws_manager = ws_manager

@router.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    if _ws_manager is None:
        logger.error("ws_manager has not been initialized in ws router")
        await websocket.close()
        return

    await _ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        _ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error("WebSocket exception: %s", e)
        _ws_manager.disconnect(websocket)
