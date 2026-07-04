"""
State Diffing Engine.
Compares discovered subdomains (findings) and crawled URLs to existing records in the database,
flagging net-new assets to highlight infrastructure drift since the last system check.
"""
from datetime import datetime, timezone
from sqlalchemy import select
from core.models import Finding, CrawledURL

async def process_subdomain_diff(session, target_id: str, job_id: str | None, subdomain: str, fhash: str) -> bool:
    """
    Checks if a subdomain (represented by its finding hash) exists in the database.
    If it exists, updates last_seen and sets is_new = False.
    If it is new, returns True (meaning it is net-new).
    """
    result = await session.execute(
        select(Finding).where(Finding.hash == fhash)
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        existing.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
        existing.is_new = False
        if job_id:
            existing.job_id = job_id
        await session.commit()
        return False
    return True


async def process_url_diff(session, target_id: str, job_id: str | None, url: str) -> bool:
    """
    Checks if a crawled URL exists for the target in the database.
    If it exists, updates last_seen / updated_at and sets is_new = False.
    If it is new, returns True (meaning it is net-new).
    """
    result = await session.execute(
        select(CrawledURL).where(
            CrawledURL.target_id == target_id,
            CrawledURL.url == url
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        existing.last_seen = now
        existing.updated_at = now
        existing.is_new = False
        if job_id:
            existing.job_id = job_id
        await session.commit()
        return False
    return True


async def process_discovered_subdomain_diff(session, target_id: str, subdomain: str, source: str) -> bool:
    """
    Checks if a subdomain exists in the discovered_subdomains table for the target.
    If it exists, updates last_seen and sets is_new = False.
    If it is new, inserts a new record and returns True (meaning it is net-new).
    """
    from core.models import DiscoveredSubdomain
    result = await session.execute(
        select(DiscoveredSubdomain).where(
            DiscoveredSubdomain.target_id == target_id,
            DiscoveredSubdomain.subdomain == subdomain
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        existing.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
        existing.is_new = False
        await session.commit()
        return False
    else:
        new_sub = DiscoveredSubdomain(
            target_id=target_id,
            subdomain=subdomain,
            source=source,
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
            last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
            is_new=True,
            risk_score=0.0,
            tech_stack=[]
        )
        session.add(new_sub)
        await session.commit()
        return True

