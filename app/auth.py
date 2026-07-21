from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, UTC

from app.contracts import UserCreate
from app.hash import hash_password, verify_password
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


#user authentication function with lockout mechanism
async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    # 1. Check if user exists
    query = select(User).where(User.email == email)
    result = await db.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials"
        )

    #ACCEPTANCE CRITERIA: Reject instantly if lockout is active
    now = datetime.now(UTC)
    if user.lockout_until and user.lockout_until > now:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Account locked due to multiple failed attempts. Try again later."
        )

    #Verify Password
    is_password_correct = verify_password(password, user.password_hash)

    if not is_password_correct:
        #Increment attempt counter on failure
        user.failed_login_attempts += 1
        
        # 5th failure = 15-minute lockout
        if user.failed_login_attempts >= 5:
            user.lockout_until = now + timedelta(minutes=15)
        
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials"
        )

    # Reset counters
    user.failed_login_attempts = 0
    user.lockout_until = None
    await db.commit()

    return user