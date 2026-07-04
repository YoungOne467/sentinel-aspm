import platform
platform._wmi = None

import os
from pathlib import Path

TEST_DB_PATH = Path(__file__).resolve().parents[1] / "scratch" / "pytest_test.db"
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("SENTINEL_DB_PATH", str(TEST_DB_PATH))
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{TEST_DB_PATH}")
os.environ.setdefault("SYNC_DATABASE_URL", f"sqlite:///{TEST_DB_PATH}")

import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from main import app
from core.database import init_db

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session", autouse=True)
async def setup_db():
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    init_db()
    yield

@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
