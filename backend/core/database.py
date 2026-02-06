"""
🗄️ Database Configuration and Session Management
Centralized database setup for all models and API endpoints

FIX 2025-01-26: Simplified session management to prevent:
- Connection leaks (zombie connections exhausting pool)
- InterfaceError "another operation in progress" 
- Event loop closed errors
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Database URLs from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://martial_user:martial_pass@localhost:5432/martial_arts_db"
)

DATABASE_URL_ASYNC = os.getenv(
    "DATABASE_URL_ASYNC",
    "postgresql+asyncpg://martial_user:martial_pass@localhost:5432/martial_arts_db"
)

# Sync engine (for init_database.py and migrations)
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=5,
        max_overflow=10,
        pool_timeout=30,
        pool_pre_ping=True,
        pool_recycle=300,
        echo=False
    )

# Async engine (for FastAPI endpoints)
# FIX 2025-01-26: Simplified pool settings
async_engine = create_async_engine(
    DATABASE_URL_ASYNC,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_pre_ping=False,  # Disabled - causes race conditions
    pool_recycle=300,
    echo=False
)

# Sync session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# Alias for backward compatibility
async_session_maker = AsyncSessionLocal

# Declarative base for all models
Base = declarative_base()


def init_db():
    """Initialize database by creating all tables (sync)"""
    Base.metadata.create_all(bind=engine)


async def get_db_optional():
    """
    FastAPI async dependency for OPTIONAL database sessions.
    Returns None if database is unavailable.

    FIX 2026-01-26: Simplified to avoid 'generator didn't stop after athrow()' error.
    Now just wraps get_db() behavior - if DB fails, the error propagates naturally.
    """
    if AsyncSessionLocal is None:
        yield None
        return

    session = AsyncSessionLocal()
    try:
        yield session
    finally:
        await session.close()


async def get_db():
    """
    FastAPI async dependency for database sessions.
    Use with: db: AsyncSession = Depends(get_db)

    FIX 2025-01-26: SIMPLIFIED VERSION
    - Removed SELECT 1 test (causes "another operation in progress" error)
    - Always close session in finally block
    - Let actual queries fail naturally if DB is down
    """
    from fastapi import HTTPException

    if AsyncSessionLocal is None:
        raise HTTPException(status_code=503, detail="Database not configured")

    session = AsyncSessionLocal()
    try:
        yield session
    finally:
        await session.close()
