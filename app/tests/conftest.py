import asyncio
from urllib.parse import urlparse

import asyncpg
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

import app.models  # noqa: F401  (registers all tables on Base.metadata)
from app.auth import ensure_role
from app.config import settings
from app.database import Base
from app.hash import hash_password
from app.models import User, UserRole
from app.roles import Role

# Tests run against a dedicated database, never the dev database the app
# points at. conftest swaps the database name in DATABASE_URL and creates the
# database on the fly, so the `drop_all`/`create_all` cycle below can't destroy
# local data.
TEST_DATABASE_NAME = "fastapi_db_test"


def _test_database_url() -> str:
    url = urlparse(settings.DATABASE_URL.replace("+asyncpg", "", 1))
    url = url._replace(path=f"/{TEST_DATABASE_NAME}")
    return url.geturl().replace("://", "+asyncpg://", 1)


async def _create_test_database_if_missing() -> None:
    url = urlparse(settings.DATABASE_URL.replace("+asyncpg", "", 1))
    conn = await asyncpg.connect(
        database="postgres",
        host=url.hostname,
        port=url.port or 5432,
        user=url.username,
        password=url.password,
    )
    try:
        exists = await conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", TEST_DATABASE_NAME
        )
        if not exists:
            await conn.execute(f'CREATE DATABASE "{TEST_DATABASE_NAME}"')
    finally:
        await conn.close()


asyncio.run(_create_test_database_if_missing())

connect_args = (
    {"statement_cache_size": 0}
    if settings.DATABASE_URL.startswith("postgresql+asyncpg")
    else {}
)
# NullPool: every connection is fresh and owned by the event loop that created
# it. pytest runs each async test on a different loop and TestClient on its
# own loop, so a shared pool would hand one loop a connection from another.
test_engine = create_async_engine(
    _test_database_url(), poolclass=NullPool, connect_args=connect_args
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


ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "admin-pass!"


@pytest.fixture
def admin_headers(client):
    """Bearer header for an admin created directly in the test database."""

    async def _seed_admin() -> None:
        async with TestSessionLocal() as db:
            admin = User(email=ADMIN_EMAIL, password_hash=hash_password(ADMIN_PASSWORD))
            db.add(admin)
            await db.flush()
            admin_role = await ensure_role(db, Role.ADMIN.value, "Administrator")
            db.add(UserRole(user_id=admin.id, role_id=admin_role.id))
            await db.commit()

    asyncio.run(_seed_admin())
    response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['accessToken']}"}
