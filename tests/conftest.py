import asyncio
import pytest
from typing import AsyncGenerator, Generator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from redis.asyncio import Redis
import redis.asyncio as redis
from datetime import datetime, timedelta, timezone

from src.main import app
from src.core.db import Base, get_db
from src.core.redis import get_redis
from src.core.config import settings
from src.models.user import User, UserRole
from src.core.security import get_password_hash


# Test database URL (use SQLite for tests)
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"
TEST_REDIS_URL = "redis://localhost:6379/1"  # Use DB 1 for testing


test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},  # Needed for SQLite
)

# Create test session factory
test_async_session_factory = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)

# Test Redis pool
test_redis_pool = redis.ConnectionPool.from_url(
    TEST_REDIS_URL, decode_responses=True, max_connections=10
)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
async def setup_db():
    """Create tables before each test and drop them after."""

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a test database session."""
    async with test_async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@pytest.fixture
async def redis_client() -> AsyncGenerator[Redis, None]:
    """Provide a test Redis client."""
    client = redis.Redis(connection_pool=test_redis_pool)
    try:
        # Clear test database before each test
        await client.flushdb()
        yield client
    finally:
        await client.close()


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user in the database."""
    user = User(
        email="test@example.com",
        hashed_password=get_password_hash("TestPass123!"),
        full_name="Test User",
        role=UserRole.USER,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_admin(db_session: AsyncSession) -> User:
    """Create a test admin in the database."""
    admin = User(
        email="admin@example.com",
        hashed_password=get_password_hash("AdminPass123!"),
        full_name="Admin User",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    return admin


@pytest.fixture
async def test_inactive_user(db_session: AsyncSession) -> User:
    """Create an inactive test user."""
    user = User(
        email="inactive@example.com",
        hashed_password=get_password_hash("InactivePass123!"),
        full_name="Inactive User",
        role=UserRole.USER,
        is_active=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return 

@pytest.fixture
async def client(db_session: AsyncSession, redis_client:Redis )->AsyncGenerator[AsyncClient, None]:
    """Provide a test HTTP client with overridden dependencies"""
    async def overried_get_db():
        yield db_session

    async def override_get_redis():
        yield redis_client



    app.dependency_overrides[get_db] = overried_get_db
    app.dependency_overrides[get_redis] = override_get_redis

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
