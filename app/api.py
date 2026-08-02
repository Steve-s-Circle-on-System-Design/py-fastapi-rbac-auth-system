from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

import app.contracts as contracts
from app.auth import create_new_user, login, logout, refresh_token
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


@router.post("/auth/login", response_model=contracts.TokenPair, tags=["Authentication"])
async def login_user(
    credentials: contracts.LoginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await login(db, credentials, request)


@router.post(
    "/auth/refresh", response_model=contracts.TokenPair, tags=["Authentication"]
)
async def refresh_user_token(
    payload: contracts.RefreshTokenRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await refresh_token(db, payload.refresh_token, request)


@router.post(
    "/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["Authentication"]
)
async def logout_user(
    payload: contracts.RefreshTokenRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    await logout(db, payload.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
