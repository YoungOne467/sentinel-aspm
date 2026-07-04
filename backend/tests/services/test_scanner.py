import pytest
from sqlalchemy import select, delete
from core.database import AsyncSessionLocal
from core.models import Target
from services.scanner import list_targets_service

@pytest.mark.asyncio
async def test_list_targets_service_empty(setup_db):
    async with AsyncSessionLocal() as session:
        await session.execute(delete(Target))
        await session.commit()
        targets = await list_targets_service(session)
        assert targets == []

@pytest.mark.asyncio
async def test_list_targets_service_with_data(setup_db):
    async with AsyncSessionLocal() as session:
        await session.execute(delete(Target))
        await session.commit()
        t1 = Target(name="Target 1", host="host1.com", risk_score=10.0, tags=["tag1"], notes="notes1", tech_stack=["stack1"], known_cves=[])
        t2 = Target(name="Target 2", host="host2.com", risk_score=20.0, tags=["tag2"], notes="notes2", tech_stack=["stack2"], known_cves=[])
        session.add(t1)
        session.add(t2)
        await session.commit()

        targets = await list_targets_service(session)
        assert len(targets) == 2
        # ordered by risk_score desc, so t2 should be first
        assert targets[0]["name"] == "Target 2"
        assert targets[1]["name"] == "Target 1"
        assert targets[0]["tags"] == ["tag2"]
        assert targets[0]["notes"] == "notes2"
        assert targets[0]["tech_stack"] == ["stack2"]

@pytest.mark.asyncio
async def test_list_targets_service_edge_cases(setup_db):
    async with AsyncSessionLocal() as session:
        await session.execute(delete(Target))
        await session.commit()
        # None lists and strings
        t3 = Target(name="Target 3", host="host3.com", risk_score=None, tags=None, notes=None, tech_stack=None, known_cves=None, created_at=None, updated_at=None)
        session.add(t3)
        await session.commit()

        targets = await list_targets_service(session)
        assert len(targets) == 1
        target = targets[0]
        assert target["name"] == "Target 3"
        assert target["risk_score"] == 0.0
        assert target["tags"] == []
        # DB defaults notes to empty string if None isn't explicitly supported in the schema
        assert target["notes"] in [None, ""]
        assert target["tech_stack"] == []
        assert target["known_cves"] == []

        # Test default handling manually if it defaults
        assert target["created_at"] is not None
        assert target["updated_at"] is not None

        # specifically test with None object mock to see how None handles
        t3.created_at = None
        t3.updated_at = None
        await session.commit()

        targets = await list_targets_service(session)
        target = targets[0]
        assert target["created_at"] is None
        assert target["updated_at"] is None
