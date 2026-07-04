import os
import json
import pytest
import psutil
from sqlalchemy import text
from unittest.mock import MagicMock, patch
from core.database import MicroBatchWriter, EMERGENCY_DUMP_PATH, AsyncSessionLocal
from core.models import Finding
from core.orchestrator import kill_process_tree

@pytest.mark.asyncio
async def test_micro_batch_writer_buffer_ceiling():
    # Remove emergency dump file if exists
    if os.path.exists(EMERGENCY_DUMP_PATH):
        os.remove(EMERGENCY_DUMP_PATH)

    # Create batch writer with a large batch size so flushing doesn't trigger naturally
    # The cap in the class is hardcoded at 1000 items. Let's push 1005 items to trigger it.
    writer = MicroBatchWriter(max_batch=2000, flush_interval=100.0)
    
    # We need dummy Finding objects
    dummy_findings = [
        Finding(title=f"Finding {i}", severity="high", hash=f"hash_{i}")
        for i in range(1005)
    ]

    # Enqueue them all
    await writer.enqueue_many(dummy_findings)

    # Since cap is 1000, the buffer should hold exactly 1000 items
    assert len(writer._buffer) == 1000

    # The remaining 5 oldest items should have been popped and written to EMERGENCY_DUMP_PATH
    assert os.path.exists(EMERGENCY_DUMP_PATH)

    with open(EMERGENCY_DUMP_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    assert len(lines) == 5
    
    # The oldest items should be the first ones (Finding 0 to Finding 4)
    first_line_data = json.loads(lines[0])
    assert "Finding 0" in first_line_data["title"]

    last_line_data = json.loads(lines[4])
    assert "Finding 4" in last_line_data["title"]

    # Clean up
    if os.path.exists(EMERGENCY_DUMP_PATH):
        os.remove(EMERGENCY_DUMP_PATH)


def test_kill_process_tree_access_denied_handling():
    mock_proc = MagicMock()
    mock_proc.pid = 88888
    
    with patch("psutil.Process") as mock_psutil_proc:
        # Mock psutil.Process to throw AccessDenied
        mock_psutil_proc.side_effect = psutil.AccessDenied(pid=88888)
        
        # Should catch AccessDenied and try direct fallback termination on Popen object
        kill_process_tree(mock_proc)
        
        mock_proc.terminate.assert_called_once()
        mock_proc.wait.assert_called_once_with(timeout=2.0)


@pytest.mark.asyncio
async def test_sqlite_pragma_wal_mode():
    # Make a quick query to verify engine executes connection pragma
    async with AsyncSessionLocal() as session:
        result = await session.execute(text("PRAGMA journal_mode;"))
        mode = result.scalar()
        assert mode.lower() == "wal"

        result = await session.execute(text("PRAGMA foreign_keys;"))
        fk = result.scalar()
        assert fk == 1
