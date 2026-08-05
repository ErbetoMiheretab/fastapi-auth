from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from core.redis import get_redis
import redis.asyncio as redis
import time
import logging

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using Redis.

    Limits requests per IP address within a time window.
    """

    def __init__(
        self,
        app: ASGIApp,
        max_requests: int = 20,
        window_seconds: int = 60,
        excluded_paths: list | None = None,
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.excluded_paths = excluded_paths or [
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)

        # Get client IP
        client_ip = self._get_client_ip(request)

        # Check rate limit
        try:
            async for redis_client in get_redis():
                is_limited = await self._check_rate_limit(redis_client, client_ip)
                if is_limited:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Too many requests. Please try again later.",
                        headers={"Retry-After": str(self.window_seconds)},
                    )
        except HTTPException:
            raise
        except redis.ConnectionError as e:
            logger.error(f"Rate limit check failed: {e}")
            # If Redis is down, allow the request through

        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request headers or direct client."""
        # Check for forwarded IP (if behind proxy)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        # Check for real IP
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fallback to client host
        return request.client.host if request.client else "unknown"

    async def _check_rate_limit(
        self, redis_client: redis.Redis, client_ip: str
    ) -> bool:
        """
        Check if client has exceeded rate limit.
        Returns True if rate limited, False otherwise.
        """

        key = f"rate_limit:{client_ip}"
        current_time = time.time()
        window_start = current_time - self.window_seconds

        # Use Redis pipeline for atomic ops
        pipe = redis_client.pipeline()

        # Remove expired entries
        pipe.zremrangebyscore(key, 0, window_start)

        # Count requests in current window
        pipe.zcard(key)

        # Add current request timestamp
        pipe.zadd(key, {str(current_time): current_time})

        # set expiry on the key
        pipe.expire(key, self.window_seconds * 2)

        results = await pipe.execute()

        request_count = results[1]

        return request_count >= self.max_requests
