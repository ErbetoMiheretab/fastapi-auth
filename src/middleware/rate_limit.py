import ipaddress
import logging
import os
import time

import redis.asyncio as redis
from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from src.core.redis import get_redis

logger = logging.getLogger(__name__)


def _parse_trusted_proxies() -> set[str]:
    """
    Read the TRUSTED_PROXY_IPS environment variable and return a set of
    normalised IP strings.  Accepts individual IPs and CIDR ranges.
    Example env value:  "10.0.0.1,172.16.0.0/12,192.168.1.0/24"
    """
    raw = os.getenv("TRUSTED_PROXY_IPS", "").strip()
    if not raw:
        return set()
    trusted: set[str] = set()
    for entry in raw.split(","):
        entry = entry.strip()
        if entry:
            trusted.add(entry)
    return trusted


# Parsed once at import time; add to .env as needed.
_TRUSTED_PROXY_IPS: set[str] = _parse_trusted_proxies()


def _is_trusted_proxy(ip: str) -> bool:
    """Return True if *ip* is in the trusted proxy list / ranges."""
    if not _TRUSTED_PROXY_IPS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in _TRUSTED_PROXY_IPS:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def _resolve_client_ip(request: Request) -> str:
    """
    Return the real client IP.

    Proxy headers (X-Forwarded-For / X-Real-IP) are **only trusted when the
    direct TCP connection originates from a known proxy IP**.  If no trusted
    proxy IPs are configured, or the direct peer is not in the list, we fall
    back to the raw socket address so clients cannot spoof their own IP.
    """
    direct_ip = request.client.host if request.client else None

    if direct_ip and _is_trusted_proxy(direct_ip):
        # Trust proxy headers only from known proxies.
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # X-Forwarded-For: client, proxy1, proxy2  — take the leftmost
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

    # Direct connection or untrusted proxy — use the real socket address.
    return direct_ip or "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    General rate-limiting middleware backed by Redis.
    Uses a sliding-window algorithm keyed on client IP.
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
        if any(request.url.path.startswith(p) for p in self.excluded_paths):
            return await call_next(request)

        client_ip = _resolve_client_ip(request)

        try:
            async for redis_client in get_redis():
                if await self._check_rate_limit(redis_client, client_ip):
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Too many requests. Please try again later.",
                        headers={"Retry-After": str(self.window_seconds)},
                    )
        except HTTPException:
            raise
        except redis.ConnectionError as e:
            logger.error(f"Rate limit Redis error: {e}")
            # Fail open — allow the request if Redis is unavailable.

        return await call_next(request)

    async def _check_rate_limit(self, redis_client: redis.Redis, client_ip: str) -> bool:
        """
        Sliding-window rate-limit check.
        Returns True if the client has exceeded max_requests in window_seconds.
        """
        key = f"rate_limit:{client_ip}"
        now = time.time()
        window_start = now - self.window_seconds

        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)   # drop expired entries
        pipe.zcard(key)                                # count remaining
        pipe.zadd(key, {str(now): now})               # record this request
        pipe.expire(key, self.window_seconds * 2)     # rolling TTL
        results = await pipe.execute()

        return results[1] >= self.max_requests


class AuthRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Stricter rate-limiting for authentication endpoints.
    After *max_attempts* failures within *window_seconds*, the IP is locked
    out for *lockout_seconds*.
    """

    AUTH_PATHS = ("/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/refresh")

    def __init__(
        self,
        app: ASGIApp,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
    ):
        super().__init__(app)
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds

    async def dispatch(self, request: Request, call_next):
        if not any(request.url.path.startswith(p) for p in self.AUTH_PATHS):
            return await call_next(request)

        client_ip = _resolve_client_ip(request)

        try:
            async for redis_client in get_redis():
                lockout_key = f"auth_lockout:{client_ip}"
                if await redis_client.exists(lockout_key):
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Too many failed attempts. Try again later.",
                        headers={"Retry-After": str(self.lockout_seconds)},
                    )
        except HTTPException:
            raise
        except redis.ConnectionError as e:
            logger.error(f"Auth rate limit Redis error: {e}")

        response = await call_next(request)

        # On auth failure, increment the attempt counter.
        if response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
            try:
                async for redis_client in get_redis():
                    attempt_key = f"auth_attempts:{client_ip}"
                    now = time.time()
                    window_start = now - self.window_seconds

                    pipe = redis_client.pipeline()
                    pipe.zremrangebyscore(attempt_key, 0, window_start)
                    pipe.zadd(attempt_key, {str(now): now})
                    pipe.zcard(attempt_key)
                    pipe.expire(attempt_key, self.window_seconds * 2)
                    results = await pipe.execute()

                    if results[2] >= self.max_attempts:
                        lockout_key = f"auth_lockout:{client_ip}"
                        await redis_client.setex(lockout_key, self.lockout_seconds, "1")
                        logger.warning(f"IP {client_ip} locked out after {self.max_attempts} failed auth attempts")
            except redis.ConnectionError as e:
                logger.error(f"Auth attempt tracking Redis error: {e}")

        return response
