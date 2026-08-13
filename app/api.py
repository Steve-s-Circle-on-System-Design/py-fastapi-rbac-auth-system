from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

import app.contracts as contracts
from app.auth import create_new_user, login, logout, refresh_token
from app.database import get_db
from app.guards import RolesGuard
from app.roles import Role, Roles
from app.security import CurrentUser

router = APIRouter()


@router.post(
    "/users",
    response_model=contracts.UserRead,
    status_code=status.HTTP_201_CREATED,
    tags=["User Creation"],
)
@Roles(Role.ADMIN)
async def create_user(
    user: contracts.UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(RolesGuard())],
):
    return await create_new_user(db, user)


@router.get("/admin/dashboard", tags=["Admin"])
@Roles(Role.ADMIN)
async def admin_dashboard(user: Annotated[CurrentUser, Depends(RolesGuard())]):
    """Example endpoint demonstrating the @Roles + RolesGuard pattern.

    Any endpoint can be locked the same way:
        @router.get("/some/path")
        @Roles(Role.ADMIN)  # or @Roles(Role.ADMIN, Role.USER) for multiple tiers
        async def handler(user: CurrentUser = Depends(RolesGuard())):
            ...
    """
    return {"message": "Welcome to the admin dashboard", "user_id": str(user.id)}


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
