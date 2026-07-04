"""
Feed Sync Engine — automated retrieval and indexing of vulnerability templates.
Syncs with trusted open-source repositories (e.g., Nuclei templates) via GitHub API.
Runs on a 24-hour cycle or on-demand.
"""
import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import FeedTemplate, gen_id

logger = logging.getLogger(__name__)

# ─── Configuration ─────────────────────────────────────────────────────────────

GITHUB_API = "https://api.github.com"
DEFAULT_FEEDS = [
    {
        "name": "nuclei-templates",
        "owner": "projectdiscovery",
        "repo": "nuclei-templates",
        "path": "",  # root
        "branch": "main",
    },
]
SYNC_INTERVAL_HOURS = 24
TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "templates",
)


class FeedSyncEngine:
    """Manages periodic sync of vulnerability definitions from GitHub repos."""

    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_sync: Optional[datetime] = None
        self._status = "idle"
        self._stats = {"synced": 0, "errors": 0}

    @property
    def status(self) -> dict:
        return {
            "running": self._running,
            "status": self._status,
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "stats": self._stats.copy(),
        }

    async def start(self):
        """Start the periodic sync loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._sync_loop())
        logger.info("FeedSyncEngine started (interval=%dh)", SYNC_INTERVAL_HOURS)

    async def stop(self):
        """Stop the sync loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def sync_now(self) -> dict:
        """Trigger an immediate sync cycle."""
        return await self._do_sync()

    async def _sync_loop(self):
        """Background loop running every 24 hours."""
        while self._running:
            try:
                await self._do_sync()
            except Exception as e:
                logger.error("Feed sync cycle error: %s", e)
                self._stats["errors"] += 1
            await asyncio.sleep(SYNC_INTERVAL_HOURS * 3600)

    async def _do_sync(self) -> dict:
        """Execute one sync cycle across all configured feeds."""
        self._status = "syncing"
        total_new = 0
        total_updated = 0

        os.makedirs(TEMPLATES_DIR, exist_ok=True)

        async with httpx.AsyncClient(timeout=30.0) as client:
            for feed in DEFAULT_FEEDS:
                try:
                    new, updated = await self._sync_feed(client, feed)
                    total_new += new
                    total_updated += updated
                except Exception as e:
                    logger.error("Failed to sync feed %s: %s", feed["name"], e)
                    self._stats["errors"] += 1

        self._last_sync = datetime.now(timezone.utc)
        self._status = "idle"
        self._stats["synced"] += total_new + total_updated

        result = {"new": total_new, "updated": total_updated, "timestamp": self._last_sync.isoformat()}
        logger.info("Feed sync complete: %d new, %d updated", total_new, total_updated)
        return result

    async def _sync_feed(self, client: httpx.AsyncClient, feed: dict) -> tuple[int, int]:
        """Sync a single feed repository. Returns (new_count, updated_count)."""
        # Fetch recent commits to get changed files
        url = f"{GITHUB_API}/repos/{feed['owner']}/{feed['repo']}/commits"
        params = {"sha": feed.get("branch", "main"), "per_page": 10}

        token = os.environ.get("GITHUB_TOKEN")
        headers = {}
        if token:
            headers["Authorization"] = f"token {token}"

        resp = await client.get(url, params=params, headers=headers)
        if resp.status_code == 403:
            logger.warning("GitHub API rate limit — skipping feed %s", feed["name"])
            return 0, 0
        resp.raise_for_status()

        commits = resp.json()
        new_count = 0
        updated_count = 0

        # Process files from recent commits
        for commit in commits[:5]:
            commit_url = f"{GITHUB_API}/repos/{feed['owner']}/{feed['repo']}/commits/{commit['sha']}"
            detail_resp = await client.get(commit_url, headers=headers)
            if detail_resp.status_code != 200:
                continue

            commit_data = detail_resp.json()
            for file_info in commit_data.get("files", [])[:50]:
                filename = file_info.get("filename", "")
                if not filename.endswith((".yaml", ".yml")):
                    continue

                template_id = filename.replace("/", ":").replace(".yaml", "").replace(".yml", "")

                async with AsyncSessionLocal() as session:
                    result = await session.execute(
                        select(FeedTemplate).where(
                            FeedTemplate.source == feed["name"],
                            FeedTemplate.template_id == template_id,
                        )
                    )
                    existing = result.scalar_one_or_none()

                    if existing:
                        existing.last_updated = datetime.now(timezone.utc).replace(tzinfo=None)
                        updated_count += 1
                    else:
                        new_template = FeedTemplate(
                            id=gen_id(),
                            source=feed["name"],
                            template_id=template_id,
                            name=os.path.basename(filename),
                            severity="info",
                            tags=[],
                            file_path=filename,
                        )
                        session.add(new_template)
                        new_count += 1
                    await session.commit()

        return new_count, updated_count

    async def get_templates(self, source: Optional[str] = None, severity: Optional[str] = None) -> list:
        """Query stored templates."""
        async with AsyncSessionLocal() as session:
            query = select(FeedTemplate)
            if source:
                query = query.where(FeedTemplate.source == source)
            if severity:
                query = query.where(FeedTemplate.severity == severity)
            result = await session.execute(query.limit(200))
            return [
                {
                    "id": t.id, "source": t.source, "template_id": t.template_id,
                    "name": t.name, "severity": t.severity, "tags": t.tags,
                    "file_path": t.file_path, "last_updated": t.last_updated.isoformat() if t.last_updated else None,
                }
                for t in result.scalars().all()
            ]


# Global singleton
feed_sync = FeedSyncEngine()
