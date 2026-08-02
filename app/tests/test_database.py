import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.database import engine, get_db


def test_engine_is_async():
    assert isinstance(engine, AsyncEngine)


@pytest.mark.asyncio
async def test_get_db_yields_session():
    async for db in get_db():
        assert isinstance(db, AsyncSession)
        result = await db.execute(text("SELECT 1"))
        assert result.scalar() == 1
