from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

import app.contracts as contracts
from app.auth import create_new_user
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
async def create_user(
    user: contracts.UserCreate, db: Annotated[AsyncSession, Depends(get_db)]
):
    return await create_new_user(db, user)

@router.get("/admin/dashboard", tags=["Admin"])
@Roles(Role.ADMIN)
async def admin_dashboard(user: CurrentUser = Depends(RolesGuard())):
    """Example endpoint demonstrating the @Roles + RolesGuard pattern.
 
    Any endpoint can be locked the same way:
        @router.get("/some/path")
        @Roles(Role.ADMIN)  # or @Roles(Role.ADMIN, Role.USER) for multiple tiers
        async def handler(user: CurrentUser = Depends(RolesGuard())):
            ...
    """
    return {"message": "Welcome to the admin dashboard", "user_id": str(user.id)}
