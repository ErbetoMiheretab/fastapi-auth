from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from core.config import settings


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


async def get_db() -> AsyncSession:
    """
    FastAPI dependency that provides an async database session.
    Automatically closes the session when the request is done.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
