from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, status
from sqlalchemy.ext.asyncio import AsyncSession

import app.contracts as contracts
from app.auth import create_new_user
from app.database import Base, engine, get_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(lifespan=lifespan)


@app.post(
    "/users",
    response_model=contracts.UserRead,
    status_code=status.HTTP_201_CREATED,
    tags=["User Creation"],
)
async def create_user(
    user: contracts.UserCreate, db: Annotated[AsyncSession, Depends(get_db)]
):
    return await create_new_user(db, contracts.UserRead)
