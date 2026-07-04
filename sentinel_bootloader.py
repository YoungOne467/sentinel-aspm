"""
SENTINEL hibernation bootloader.

This process owns the app lifecycle:
1. Run FastAPI + Vite for the active dashboard.
2. Watch scratch/hibernate.sig.
3. Stop the app stack to free RAM.
4. Run backend/offline_ai_processor.py while Ollama has the memory budget.
5. Restart the app stack.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

LOGGER = logging.getLogger("sentinel.bootloader")


@dataclass(frozen=True)
class BootloaderConfig:
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    backend_port: int = 8000
    frontend_port: int = 5174
    poll_interval_seconds: float = 1.0

    @property
    def backend_cwd(self) -> Path:
        return self.project_root / "backend"

    @property
    def frontend_cwd(self) -> Path:
        return self.project_root / "aspm-frontend"

    @property
    def scratch_dir(self) -> Path:
        return self.project_root / "scratch"

    @property
    def signal_file(self) -> Path:
        return self.scratch_dir / "hibernate.sig"

    @property
    def backend_python(self) -> Path:
        if os.name == "nt":
            candidate = self.backend_cwd / "venv" / "Scripts" / "python.exe"
        else:
            candidate = self.backend_cwd / "venv" / "bin" / "python"
        return candidate if candidate.exists() else Path(sys.executable)

    @property
    def npm_executable(self) -> str:
        return "npm.cmd" if os.name == "nt" else "npm"

    @property
    def backend_command(self) -> list[str]:
        return [
            str(self.backend_python),
            "-m",
            "uvicorn",
            "main:app",
            "--host",
            "0.0.0.0",
            "--port",
            str(self.backend_port),
        ]

    @property
    def frontend_command(self) -> list[str]:
        return [
            self.npm_executable,
            "run",
            "dev",
            "--",
            "--port",
            str(self.frontend_port),
        ]

    @property
    def ai_batch_command(self) -> list[str]:
        return [str(self.backend_python), str(self.backend_cwd / "offline_ai_processor.py")]


class SentinelBootloader:
    def __init__(self, config: BootloaderConfig | None = None):
        self.config = config or BootloaderConfig()
        self.backend_process: subprocess.Popen | None = None
        self.frontend_process: subprocess.Popen | None = None
        self._stopping = False

    def run_forever(self) -> None:
        self.config.scratch_dir.mkdir(parents=True, exist_ok=True)
        self.remove_signal()
        self.start_active_stack()
        try:
            while not self._stopping:
                if self.config.signal_file.exists():
                    self.hibernate_cycle()
                time.sleep(self.config.poll_interval_seconds)
        except KeyboardInterrupt:
            LOGGER.info("Bootloader interrupted.")
        finally:
            self.stop_active_stack()

    def start_active_stack(self) -> None:
        LOGGER.info("Starting active SENTINEL stack.")
        self.backend_process = self.spawn("backend", self.config.backend_command, self.config.backend_cwd)
        self.frontend_process = self.spawn("frontend", self.config.frontend_command, self.config.frontend_cwd)

    def stop_active_stack(self) -> None:
        LOGGER.info("Stopping active SENTINEL stack.")
        self.terminate_process("frontend", self.frontend_process)
        self.terminate_process("backend", self.backend_process)
        self.frontend_process = None
        self.backend_process = None

    def hibernate_cycle(self) -> None:
        LOGGER.info("Hibernate signal detected: %s", self.config.signal_file)
        self.remove_signal()
        self.stop_active_stack()
        self.run_ai_batch()
        self.start_active_stack()

    def run_ai_batch(self) -> int:
        LOGGER.info("Running offline AI batch.")
        completed = subprocess.run(self.config.ai_batch_command, cwd=self.config.backend_cwd, check=False)
        LOGGER.info("Offline AI batch exited with code %s.", completed.returncode)
        return completed.returncode

    def remove_signal(self) -> None:
        try:
            self.config.signal_file.unlink()
        except FileNotFoundError:
            pass

    def spawn(self, name: str, command: list[str], cwd: Path) -> subprocess.Popen:
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        LOGGER.info("Spawning %s: %s", name, " ".join(command))
        return subprocess.Popen(
            command,
            cwd=cwd,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )

    def terminate_process(self, name: str, process: subprocess.Popen | None) -> None:
        if process is None or process.poll() is not None:
            return
        LOGGER.info("Terminating %s process tree (pid=%s).", name, process.pid)
        try:
            process.terminate()
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            LOGGER.warning("%s did not exit after terminate; forcing process tree.", name)
        except Exception as exc:
            LOGGER.warning("%s terminate failed: %s", name, exc)

        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                process.wait(timeout=5)
            except Exception:
                process.kill()


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> int:
    configure_logging()
    SentinelBootloader().run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
