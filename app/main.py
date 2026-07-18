import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

import model
from database import engine, Base, AsyncSessionLocal
from database_model import User, UserRole
from hash import hash_password

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(lifespan=lifespan)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

@app.post("/users", response_model=model.UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(user_in: model.UserCreate, db: AsyncSession = Depends(get_db)):
    # 1. Check if user exists
    query = select(User).where(User.email == user_in.email)
    result = await db.execute(query)
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email already registered"
        )
    
    new_user = User(
        email=user_in.email,
        password_hash=hash_password(user_in.password),
        role=UserRole.USER
    )
    
    db.add(new_user)
    try:
        await db.commit()
        await db.refresh(new_user)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Database error")
    
    return new_user





