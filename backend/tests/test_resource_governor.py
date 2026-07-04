"""
Tests for the Resource Governor module.
"""
import asyncio
from unittest.mock import patch, MagicMock

import pytest

from core import resource_governor


@pytest.fixture(autouse=True)
def _reset_governor():
    """Ensure the governor starts clean for every test."""
    resource_governor._throttled = False
    resource_governor.system_healthy.set()
    resource_governor._broadcast_fn = None
    yield
    # Cleanup: ensure monitor is stopped and event is set
    resource_governor._throttled = False
    resource_governor.system_healthy.set()


# ─── Threshold Detection ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_throttle_on_high_ram():
    """system_healthy should be cleared when RAM exceeds the throttle threshold."""
    fake_mem = MagicMock()
    fake_mem.percent = 90.0  # above 85% threshold
    fake_mem.available = 1 * 1024 * 1024 * 1024  # 1 GB

    with patch("core.resource_governor.psutil") as mock_psutil:
        mock_psutil.virtual_memory.return_value = fake_mem
        mock_psutil.cpu_percent.return_value = 30.0  # CPU is fine

        # Run one iteration of the monitor
        task = asyncio.create_task(resource_governor.monitor_system_health())
        await asyncio.sleep(0.1)

        # Let one polling cycle happen (override sleep to be instant)
        await asyncio.sleep(resource_governor.POLL_INTERVAL_SECONDS + 0.5)

        assert not resource_governor.system_healthy.is_set()
        assert resource_governor._throttled is True

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_throttle_on_high_cpu():
    """system_healthy should be cleared when CPU exceeds the throttle threshold."""
    fake_mem = MagicMock()
    fake_mem.percent = 50.0  # RAM is fine
    fake_mem.available = 8 * 1024 * 1024 * 1024

    with patch("core.resource_governor.psutil") as mock_psutil:
        mock_psutil.virtual_memory.return_value = fake_mem
        mock_psutil.cpu_percent.return_value = 95.0  # above 90% threshold

        task = asyncio.create_task(resource_governor.monitor_system_health())
        await asyncio.sleep(resource_governor.POLL_INTERVAL_SECONDS + 0.5)

        assert not resource_governor.system_healthy.is_set()
        assert resource_governor._throttled is True

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_resume_after_recovery():
    """system_healthy should be set again when utilization drops below resume thresholds."""
    fake_mem_high = MagicMock()
    fake_mem_high.percent = 90.0
    fake_mem_high.available = 1 * 1024 * 1024 * 1024

    fake_mem_low = MagicMock()
    fake_mem_low.percent = 60.0
    fake_mem_low.available = 6 * 1024 * 1024 * 1024

    call_count = 0

    def side_effect_mem():
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return fake_mem_high
        return fake_mem_low

    def side_effect_cpu(interval=None):
        nonlocal call_count
        if call_count <= 2:
            return 30.0  # CPU fine, RAM high
        return 30.0  # Both fine

    with patch("core.resource_governor.psutil") as mock_psutil:
        mock_psutil.virtual_memory.side_effect = side_effect_mem
        mock_psutil.cpu_percent.side_effect = side_effect_cpu

        task = asyncio.create_task(resource_governor.monitor_system_health())

        # Wait for throttle to engage
        await asyncio.sleep(resource_governor.POLL_INTERVAL_SECONDS + 0.5)
        assert resource_governor._throttled is True

        # Wait for recovery
        await asyncio.sleep(resource_governor.POLL_INTERVAL_SECONDS * 2 + 0.5)
        assert resource_governor.system_healthy.is_set()
        assert resource_governor._throttled is False

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_no_throttle_when_healthy():
    """system_healthy should remain set when resources are within limits."""
    fake_mem = MagicMock()
    fake_mem.percent = 50.0
    fake_mem.available = 8 * 1024 * 1024 * 1024

    with patch("core.resource_governor.psutil") as mock_psutil:
        mock_psutil.virtual_memory.return_value = fake_mem
        mock_psutil.cpu_percent.return_value = 30.0

        task = asyncio.create_task(resource_governor.monitor_system_health())
        await asyncio.sleep(resource_governor.POLL_INTERVAL_SECONDS + 0.5)

        assert resource_governor.system_healthy.is_set()
        assert resource_governor._throttled is False

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# ─── Lifecycle Helpers ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_and_stop_monitor():
    """start_monitor / stop_monitor should create and cancel the background task."""
    with patch("core.resource_governor.psutil") as mock_psutil:
        fake_mem = MagicMock()
        fake_mem.percent = 50.0
        fake_mem.available = 8 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = fake_mem
        mock_psutil.cpu_percent.return_value = 30.0

        await resource_governor.start_monitor()
        assert resource_governor._monitor_task is not None
        assert not resource_governor._monitor_task.done()

        await resource_governor.stop_monitor()
        assert resource_governor._monitor_task is None
        assert resource_governor.system_healthy.is_set()


@pytest.mark.asyncio
async def test_stop_resets_event():
    """Stopping the monitor should always leave system_healthy set."""
    resource_governor._throttled = True
    resource_governor.system_healthy.clear()

    await resource_governor.stop_monitor()

    assert resource_governor.system_healthy.is_set()
    assert resource_governor._throttled is False


# ─── get_status ────────────────────────────────────────────────────────────────

def test_get_status_returns_expected_keys():
    """get_status should include all telemetry fields."""
    with patch("core.resource_governor.psutil") as mock_psutil:
        fake_mem = MagicMock()
        fake_mem.percent = 60.0
        fake_mem.available = 6 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = fake_mem
        mock_psutil.cpu_percent.return_value = 40.0

        status = resource_governor.get_status()

    assert "throttled" in status
    assert "ram_percent" in status
    assert "ram_available_mb" in status
    assert "cpu_percent" in status
    assert "thresholds" in status
    assert status["thresholds"]["ram_throttle"] == 85.0
    assert status["thresholds"]["cpu_throttle"] == 90.0
    assert status["thresholds"]["ram_resume"] == 75.0
    assert status["thresholds"]["cpu_resume"] == 75.0


# ─── Broadcast Integration ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_broadcast_called_on_throttle():
    """The governor should broadcast a warning when it throttles."""
    messages = []

    async def mock_broadcast(msg):
        messages.append(msg)

    resource_governor.set_broadcast(mock_broadcast)

    fake_mem = MagicMock()
    fake_mem.percent = 90.0
    fake_mem.available = 1 * 1024 * 1024 * 1024

    with patch("core.resource_governor.psutil") as mock_psutil:
        mock_psutil.virtual_memory.return_value = fake_mem
        mock_psutil.cpu_percent.return_value = 30.0

        task = asyncio.create_task(resource_governor.monitor_system_health())
        await asyncio.sleep(resource_governor.POLL_INTERVAL_SECONDS + 0.5)

        assert len(messages) >= 1
        assert messages[0]["type"] == "system_alert"
        assert messages[0]["level"] == "warning"

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
