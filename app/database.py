from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from app.config import settings

connect_args = {}
if settings.DATABASE_URL.startswith("postgresql+asyncpg"):
    connect_args["statement_cache_size"] = 0
engine = create_async_engine(
    settings.DATABASE_URL, echo=False, connect_args=connect_args
)


AsyncSessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False)


Base = declarative_base()


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
