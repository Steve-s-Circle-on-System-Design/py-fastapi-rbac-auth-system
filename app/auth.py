from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.contracts import UserCreate
from app.hash import hash_password
from app.models import User, UserRole


async def create_new_user(db: AsyncSession, user: UserCreate):
    # 1. Check if user exists
    query = select(User).where(User.email == user.email)
    result = await db.execute(query)
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    new_user = User(
        email=user.email,
        password_hash=hash_password(user.password),
        role=UserRole.USER,
    )

    db.add(new_user)
    try:
        await db.commit()
        await db.refresh(new_user)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Database error") from e

    return new_user
