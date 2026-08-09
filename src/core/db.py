from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from src.core.config import settings

# create async engine

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=True,  # for sql debugging
    pool_size=10,
    max_overflow=10,  # Extra connections beyond pool_size
    pool_pre_ping=True,  # Verify conn before using,pre check if connection dead create a new one
    pool_recycle=3600,  # Recycle connections after 1 hr
)


# Create async session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


# Dependency to get DB session


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides an async database session.

    Commits are the responsibility of each route handler so that they can
    control exactly when data is flushed.  This dependency only rolls back on
    unhandled exceptions and always closes the session on exit.
    """
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
