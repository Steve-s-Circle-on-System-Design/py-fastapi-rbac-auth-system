import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

import app.models  # noqa: F401  (registers all tables on Base.metadata)
from app.config import settings
from app.database import Base

connect_args = (
    {"statement_cache_size": 0}
    if settings.DATABASE_URL.startswith("postgresql+asyncpg")
    else {}
)

# NullPool: every connection is fresh and owned by the event loop that created
# it. pytest runs each async test on a different loop and TestClient on its
# own loop, so a shared pool would hand one loop a connection from another.
test_engine = create_async_engine(
    settings.DATABASE_URL, poolclass=NullPool, connect_args=connect_args
)
TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def prepared_database():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(prepared_database):
    async with TestSessionLocal() as session:
        yield session


@pytest.fixture
def client(prepared_database):
    from fastapi.testclient import TestClient

    from app.database import get_db
    from app.main import app

    async def _override_get_db():
        async with TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.pop(get_db, None)
