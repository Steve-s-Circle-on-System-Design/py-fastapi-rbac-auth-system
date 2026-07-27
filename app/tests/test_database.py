import pytest
from sqlalchemy import text
from app.database import get_db

@pytest.mark.asyncio
async def test_database_connection():
    async for db in get_db():  
        result = await db.execute(text("SELECT 1"))
        scalar = result.scalar()
        assert scalar == 1
        break   