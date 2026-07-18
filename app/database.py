import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

#variables from  .env file
load_dotenv()

# Database URL
DATABASE_URL = os.getenv("DATABASE_URL")

#Async engine
engine = create_async_engine(DATABASE_URL, echo=True)

# Session maker for async sessions
AsyncSessionLocal = async_sessionmaker(
    bind=engine, 
    expire_on_commit=False
)

#Base class
Base = declarative_base()