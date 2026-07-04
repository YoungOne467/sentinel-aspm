import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import Target, Finding, CrawledURL, gen_id
from core.diff_engine import process_subdomain_diff, process_url_diff

@pytest.mark.asyncio
async def test_subdomain_diff_engine():
    # Setup test target
    async with AsyncSessionLocal() as session:
        target = Target(
            id=gen_id(),
            name="Diff Test Target Subdomain",
            host="diffsub.local",
            port=80
        )
        session.add(target)
        await session.commit()
        target_id = target.id

    subdomain_title = "Discovered Subdomain: api.diffsub.local"
    fhash = "test_subdomain_hash_123"

    # Ensure clean database state for this hash
    async with AsyncSessionLocal() as session:
        from sqlalchemy import delete
        await session.execute(delete(Finding).where(Finding.hash == fhash))
        await session.commit()

    # Step 1: Check diff for a net-new subdomain
    async with AsyncSessionLocal() as session:
        is_new = await process_subdomain_diff(session, target_id, None, subdomain_title, fhash)
        assert is_new is True

    # Manually add the finding as if it was processed and saved
    async with AsyncSessionLocal() as session:
        finding = Finding(
            id=gen_id(),
            target_id=target_id,
            title=subdomain_title,
            severity="info",
            category="subdomain_recon",
            hash=fhash,
            is_new=True,
            first_seen=datetime.now(timezone.utc) - timedelta(hours=1),
            last_seen=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        session.add(finding)
        await session.commit()

    # Step 2: Check diff for an existing subdomain
    async with AsyncSessionLocal() as session:
        is_new = await process_subdomain_diff(session, target_id, None, subdomain_title, fhash)
        assert is_new is False

    # Check that is_new is updated to False and last_seen is updated
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Finding).where(Finding.hash == fhash)
        )
        db_finding = result.scalar_one()
        assert db_finding.is_new is False
        assert db_finding.last_seen > db_finding.first_seen

    # Cleanup
    async with AsyncSessionLocal() as session:
        from sqlalchemy import delete
        await session.execute(delete(Finding).where(Finding.hash == fhash))
        t = await session.get(Target, target_id)
        if t:
            await session.delete(t)
        await session.commit()


@pytest.mark.asyncio
async def test_url_diff_engine():
    # Setup test target
    async with AsyncSessionLocal() as session:
        target = Target(
            id=gen_id(),
            name="Diff Test Target URL",
            host="diffurl.local",
            port=80
        )
        session.add(target)
        await session.commit()
        target_id = target.id

    url = "https://diffurl.local/api/v1/health"

    # Step 1: Check diff for a net-new URL
    async with AsyncSessionLocal() as session:
        is_new = await process_url_diff(session, target_id, None, url)
        assert is_new is True

    # Manually add the CrawledURL as if it was processed and saved
    async with AsyncSessionLocal() as session:
        crawled_url = CrawledURL(
            id=gen_id(),
            target_id=target_id,
            host="diffurl.local",
            url=url,
            is_new=True,
            first_seen=datetime.now(timezone.utc) - timedelta(hours=1),
            last_seen=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        session.add(crawled_url)
        await session.commit()

    # Step 2: Check diff for an existing URL
    async with AsyncSessionLocal() as session:
        is_new = await process_url_diff(session, target_id, None, url)
        assert is_new is False

    # Check that is_new is updated to False and last_seen is updated
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(CrawledURL).where(
                CrawledURL.target_id == target_id,
                CrawledURL.url == url
            )
        )
        db_url = result.scalar_one()
        assert db_url.is_new is False
        assert db_url.last_seen > db_url.first_seen

    # Cleanup
    async with AsyncSessionLocal() as session:
        t = await session.get(Target, target_id)
        if t:
            await session.delete(t)
            await session.commit()
