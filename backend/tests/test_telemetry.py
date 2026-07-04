import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from core.telemetry import telemetry_loop

@pytest.mark.asyncio
async def test_telemetry_loop_broadcasting():
    mock_broadcast = AsyncMock()
    
    # Patch broadcast and run the loop for a short iteration
    with patch("core.telemetry._broadcast_fn", new=mock_broadcast):
        # We run the task in the background, sleep 1.1 seconds, then cancel it
        task = asyncio.create_task(telemetry_loop())
        await asyncio.sleep(1.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
            
    # Verify that it broadcasted system telemetry
    assert mock_broadcast.called
    payload = mock_broadcast.call_args[0][0]
    assert payload["type"] == "system_telemetry"
    assert "cpu" in payload
    assert "ram" in payload
    assert "tasks" in payload
    assert isinstance(payload["cpu"], (int, float))
    assert isinstance(payload["ram"], int)
    assert isinstance(payload["tasks"], int)
