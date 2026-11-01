import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

import app.contracts as contracts
from app.auth import (
    create_new_user,
    get_user_role_names,
    login,
    logout,
    refresh_token,
    revoke_access_token,
    revoke_all_sessions,
)
from app.bootstrap import ensure_admin
from app.config import BootstrapMode, settings
from app.database import get_db
from app.guards import RolesGuard
from app.models import User
from app.roles import Role, Roles
from app.security import CurrentUser, bearer_scheme, get_current_user
from app.tokens import validate_token

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
    request: Request,
):
    host_url = str(request.base_url) if request else None
    new_user = await create_new_user(db, user, host_url=host_url)
    return contracts.UserRead(
        id=new_user.id,
        email=new_user.email,
        roles=await get_user_role_names(db, new_user.id),
    )


@router.post(
    "/bootstrap",
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def bootstrap_admin(
    payload: contracts.UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_bootstrap_token: Annotated[str | None, Header()] = None,
):
    """Create the first ADMIN when BOOTSTRAP_MODE=http in config.

    Only ever creates the first admin: once one exists every call returns 409,
    so a leaked token cannot mint more accounts.
    """
    if settings.BOOTSTRAP_MODE is not BootstrapMode.HTTP:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    token = settings.BOOTSTRAP_TOKEN
    if (
        not token
        or not x_bootstrap_token
        or not secrets.compare_digest(
            x_bootstrap_token.encode("utf-8"), token.encode("utf-8")
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bootstrap token",
        )

    if not await ensure_admin(db, payload.email, payload.password):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An admin already exists",
        )

    return {"message": "Admin created"}


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
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ] = None,
) -> Response:
    if credentials is not None:
        await revoke_access_token(credentials.credentials)
    await logout(db, payload.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/auth/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Authentication"],
)
async def logout_all_sessions(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """End every session of the caller, including the token used for this call.

    The user id comes from the token, so nobody can end someone else's sessions.
    """
    await revoke_all_sessions(db, user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/auth/verify", tags=["Authentication"])
@router.post("/auth/verify", tags=["Authentication"])
async def verify_email(token: str, db: Annotated[AsyncSession, Depends(get_db)]):
    payload = validate_token(token, expected_type="email_verification")
    raw_user_id = payload.get("user") or payload.get("sub")
    if not raw_user_id:
        raise HTTPException(status_code=400, detail="Invalid token claims")
    user_id = uuid.UUID(raw_user_id)

    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_verified = True
    user.email_verified_at = datetime.now(UTC)
    await db.commit()
    return {"message": "Email verified successfully"}
