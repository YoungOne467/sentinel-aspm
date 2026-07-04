import pytest
import json
from unittest.mock import AsyncMock, patch
from packages.execution.reconciliation import DockerReconciliationManager

class TestDockerReconciliationManager:
    @pytest.mark.asyncio
    async def test_two_pass_orphan_cleanup(self):
        # We will mock the command runner to simulate Docker CLI output
        mock_run = AsyncMock()
        manager = DockerReconciliationManager(run_cmd_fn=mock_run, grace_period_sec=5.0)

        # 1. First pass setup:
        # Two networks: sentinel-net-active, sentinel-net-orphan
        # One container cid1 active on sentinel-net-active
        def mock_cmd(args):
            cmd_str = " ".join(args)
            if "network ls" in cmd_str:
                return "sentinel-net-active\nsentinel-net-orphan\n"
            elif "ps -a -q" in cmd_str:
                return "cid1\n"
            elif "inspect cid1" in cmd_str:
                return json.dumps([{
                    "State": {"Status": "running"},
                    "NetworkSettings": {"Networks": {"sentinel-net-active": {}}}
                }])
            elif "network rm" in cmd_str:
                return ""
            return ""

        mock_run.side_effect = lambda args: mock_cmd(args)

        with patch("time.time") as mock_time:
            # Pass 1 at t=1000.0
            mock_time.return_value = 1000.0
            await manager.reconcile()

            # sentinel-net-orphan should be marked as candidate
            assert "sentinel-net-orphan" in manager.candidate_orphaned_networks
            assert manager.candidate_orphaned_networks["sentinel-net-orphan"] == 1000.0
            
            # docker network rm should NOT have been called yet
            for call_args in mock_run.call_args_list:
                assert "rm" not in call_args[0][0]

            # Pass 2 at t=1002.0 (before grace period of 5s expires)
            mock_time.return_value = 1002.0
            mock_run.reset_mock()
            await manager.reconcile()

            assert "sentinel-net-orphan" in manager.candidate_orphaned_networks
            # docker network rm should STILL not have been called
            for call_args in mock_run.call_args_list:
                assert "rm" not in call_args[0][0]

            # Pass 3 at t=1006.0 (grace period expired)
            mock_time.return_value = 1006.0
            mock_run.reset_mock()
            await manager.reconcile()

            # sentinel-net-orphan is deleted and removed from candidates
            assert "sentinel-net-orphan" not in manager.candidate_orphaned_networks
            
            # docker network rm sentinel-net-orphan must be called
            rm_called = any("rm" in c[0][0] for c in mock_run.call_args_list)
            assert rm_called is True

    @pytest.mark.asyncio
    async def test_inspect_failure_prevents_deletion(self):
        mock_run = AsyncMock()
        manager = DockerReconciliationManager(run_cmd_fn=mock_run, grace_period_sec=5.0)

        # sentinel-net-orphan is already a candidate
        manager.candidate_orphaned_networks["sentinel-net-orphan"] = 1000.0

        # Simulate inspect failure
        def mock_cmd(args):
            cmd_str = " ".join(args)
            if "network ls" in cmd_str:
                return "sentinel-net-orphan\n"
            elif "ps -a -q" in cmd_str:
                return "cid1\n"
            elif "inspect cid1" in cmd_str:
                raise RuntimeError("inspect error")
            return ""

        mock_run.side_effect = lambda args: mock_cmd(args)

        with patch("time.time") as mock_time:
            mock_time.return_value = 1010.0  # Past grace period
            await manager.reconcile()

            # Because inspect failed, the pass is aborted conservatively.
            # The candidate should NOT be deleted.
            assert "sentinel-net-orphan" in manager.candidate_orphaned_networks
            rm_called = any("rm" in c[0][0] for c in mock_run.call_args_list)
            assert rm_called is False
