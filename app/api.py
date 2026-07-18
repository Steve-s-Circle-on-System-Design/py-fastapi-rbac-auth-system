from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

import app.contracts as contracts
from app.auth import create_new_user
from app.database import get_db

router = APIRouter()


@router.post(
    "/users",
    response_model=contracts.UserRead,
    status_code=status.HTTP_201_CREATED,
    tags=["User Creation"],
)
async def create_user(
    user: contracts.UserCreate, db: Annotated[AsyncSession, Depends(get_db)]
):
    return await create_new_user(db, user)
