from typing import AsyncGenerator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

async_engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    echo=settings.DEBUG,
)

_AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autobegin=True,
)

# Exported for use by Celery worker tasks
AsyncSessionLocal = _AsyncSessionLocal

# Sync engine used ONLY by Alembic migrations — never by the application
sync_engine = create_engine(
    settings.DATABASE_URL_SYNC,
    pool_pre_ping=True,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
