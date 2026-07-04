"""
Telemetry Sequence Aggregation Module.
Queries database for chronological sequence of HTTP requests and responses (crawled URLs)
associated with a specific target's session.
"""
import logging
from typing import List, Dict, Any
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import CrawledURL

logger = logging.getLogger(__name__)

async def aggregate_session_traffic(target_id: Any) -> List[Dict[str, Any]]:
    """
    Queries database for a chronological sequence of HTTP requests and responses
    associated with a specific target's session.
    """
    target_id_str = str(target_id)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(CrawledURL)
            .where(CrawledURL.target_id == target_id_str)
            .order_by(CrawledURL.created_at.asc())
        )
        urls = result.scalars().all()
        logger.info("Aggregated %d chronological traffic items for target %s", len(urls), target_id_str)
        return [
            {
                "url": u.url,
                "method": u.method or "GET",
                "status_code": u.status_code,
            }
            for u in urls
        ]
