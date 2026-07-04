"""
URL Parser & Diffing Engine for crawlers like Katana.
Extracts endpoints, stores them in the database, and flags new URLs.
"""
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from urllib.parse import urlparse

from sqlalchemy import select
from core.database import AsyncSessionLocal, batch_writer
from core.models import CrawledURL, gen_id

logger = logging.getLogger(__name__)


def extract_host_from_url(url: str) -> str:
    """Helper to extract netloc (host) from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return "unknown"


async def ingest_katana_urls(
    target_id: str,
    job_id: str | None,
    raw_output: str,
) -> int:
    """
    Parses Katana JSON Lines output, extracts urls, checks if they are new,
    and inserts them via the batch_writer.
    """
    parsed_items: List[Dict[str, Any]] = []
    
    # Process Katana JSON Lines format
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                # Katana outputs JSON with fields like 'request' -> 'url' or direct 'request'/'url'
                # Check for standard fields
                url = data.get("request", {}).get("url") or data.get("url")
                if url:
                    parsed_items.append(data)
        except json.JSONDecodeError:
            # Fallback: maybe it's just raw urls?
            if line.startswith(("http://", "https://")):
                parsed_items.append({"url": line})

    if not parsed_items:
        return 0

    new_count = 0
    async with AsyncSessionLocal() as session:
        for item in parsed_items:
            req_field = item.get("request")
            url = None
            method = "GET"
            status_code = None

            if isinstance(req_field, dict):
                url = req_field.get("url")
                method = req_field.get("method") or "GET"
            elif isinstance(req_field, str):
                url = req_field
            else:
                url = item.get("url")

            if not url:
                continue

            resp_field = item.get("response")
            if isinstance(resp_field, dict):
                status_code = resp_field.get("status_code")

            if status_code is None:
                status_code = item.get("status_code")

            if status_code is not None:
                try:
                    status_code = int(status_code)
                except (ValueError, TypeError):
                    status_code = None

            # Parse host from URL
            host = extract_host_from_url(url)

            from core.diff_engine import process_url_diff
            is_new = await process_url_diff(session, target_id, job_id, url)

            if not is_new:
                continue

            # New URL found!
            crawled_id = gen_id()
            new_crawled = CrawledURL(
                id=crawled_id,
                job_id=job_id,
                target_id=target_id,
                host=host,
                url=url,
                method=method.upper(),
                status_code=status_code,
                has_alert=False,
                is_new=True,
            )
            await batch_writer.enqueue(new_crawled)
            new_count += 1

            import asyncio
            from core.dlp_parser import analyze_url_telemetry
            asyncio.create_task(analyze_url_telemetry(crawled_id, url, target_id))

        # Flush batch writer updates
        await batch_writer.flush()

    return new_count
