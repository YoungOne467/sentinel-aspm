"""
Fuzzer Orchestrator — automatic directory and parameter discovery.
Fires lightweight background fuzzing jobs (ffuf, arjun) when live HTTP endpoints
are registered by the main engine.
"""
import asyncio
import logging
import os
from typing import Optional, Dict, Any, List

import yaml

from core.orchestrator import orchestrator
from core.database import AsyncSessionLocal
from core.models import Job, gen_id

logger = logging.getLogger(__name__)

# ─── Default Fuzzing Configurations ───────────────────────────────────────────

DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists", "common.txt",
)

FUZZ_CONFIGS = {
    "directory_discovery": {
        "tool": "ffuf",
        "template": 'ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302,403 -o {output} -of json -t 10 -rate 50',
        "enabled": True,
        "description": "Discover hidden directories and files",
    },
    "parameter_discovery": {
        "tool": "arjun",
        "template": "arjun -u {url} -oJ {output} -t 5",
        "enabled": True,
        "description": "Discover hidden GET/POST parameters",
    },
    "vhost_discovery": {
        "tool": "ffuf",
        "template": 'ffuf -u {url} -H "Host: FUZZ.{domain}" -w {wordlist} -mc 200 -o {output} -of json -t 10',
        "enabled": False,
        "description": "Discover virtual hosts",
    },
}


class FuzzerOrchestrator:
    """Automatically fires fuzzing jobs for discovered HTTP endpoints."""

    def __init__(self):
        self._active_fuzz_jobs: Dict[str, str] = {}  # target_host -> job_id
        self._semaphore = asyncio.Semaphore(15)

    async def _run_job_with_semaphore(self, job_id: str, command: str, fuzz_type: str):
        async with self._semaphore:
            await orchestrator.execute_job(job_id, command, f"fuzz:{fuzz_type}")

    async def auto_fuzz(
        self,
        target_id: str,
        url: str,
        fuzz_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Trigger fuzzing for a discovered HTTP endpoint.
        Returns list of job creation results.
        """
        if fuzz_types is None:
            fuzz_types = ["directory_discovery"]

        results = []
        for fuzz_type in fuzz_types:
            config = FUZZ_CONFIGS.get(fuzz_type)
            if not config or not config.get("enabled"):
                continue

            # Check if tool is available
            tool_name = config["tool"]
            if not self._is_tool_available(tool_name):
                logger.warning("Tool %s not found in PATH — skipping %s", tool_name, fuzz_type)
                results.append({
                    "fuzz_type": fuzz_type,
                    "status": "skipped",
                    "reason": f"{tool_name} not found",
                })
                continue

            # Build the command
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "scratch", "fuzz_output",
            )
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"{fuzz_type}_{domain}.json")

            wordlist = DEFAULT_WORDLIST
            if not os.path.exists(wordlist):
                # Create a minimal default wordlist
                os.makedirs(os.path.dirname(wordlist), exist_ok=True)
                with open(wordlist, "w") as f:
                    f.write("\n".join([
                        "admin", "api", "login", "dashboard", "config", "test",
                        "debug", "status", "health", "docs", "swagger", "graphql",
                        "wp-admin", "wp-login", ".env", "robots.txt", "sitemap.xml",
                        "backup", "staging", "dev", "v1", "v2", "internal",
                    ]))

            command = config["template"].format(
                url=url,
                wordlist=wordlist,
                output=output_file,
                domain=domain,
            )

            # Create job in DB and execute
            job_id = gen_id()
            job = Job(
                id=job_id,
                target_id=target_id,
                tool_name=f"fuzz:{fuzz_type}",
                command=command,
                status="queued",
            )
            async with AsyncSessionLocal() as session:
                session.add(job)
                await session.commit()

            # Fire and forget via orchestrator with Semaphore gating
            asyncio.create_task(
                self._run_job_with_semaphore(job_id, command, fuzz_type)
            )
            self._active_fuzz_jobs[domain] = job_id

            results.append({
                "fuzz_type": fuzz_type,
                "job_id": job_id,
                "status": "queued",
                "command": command,
            })

        return results

    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool binary is available in PATH."""
        import shutil
        return shutil.which(tool_name) is not None

    def get_active_fuzz_jobs(self) -> Dict[str, str]:
        return self._active_fuzz_jobs.copy()


# Global singleton
fuzzer_orchestrator = FuzzerOrchestrator()
