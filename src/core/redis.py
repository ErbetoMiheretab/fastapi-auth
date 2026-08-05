import logging

import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool

from core.config import settings

logger = logging.getLogger(__name__)

# Create Redis connection pool
# Create Redis connection pool
redis_pool = ConnectionPool.from_url(
    settings.REDIS_URL,
    password=settings.REDIS_PASSWORD,
    max_connections=20,
    decode_responses=True,  # Automatically decode to strings
    socket_timeout=5,
    socket_connect_timeout=5,
    retry_on_timeout=True,
)


async def get_redis() -> redis.Redis:
    """
    FastAPI dependency that provides a Redis connection.
    """

    client = redis.Redis(connection_pool=redis_pool)
    try:
        yield client
    finally:
        await client.close()


async def check_redis_connection():
    """Verify Redis connectivity on startup."""
    try:
        client = redis.Redis(connection_pool=redis_pool)
        await client.ping()
        logger.info("Redis connection successful")
        await client.close()
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        raise
