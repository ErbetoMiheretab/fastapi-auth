import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

import redis.asyncio as redis
from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# pwd hashing
def verify_password(plain_pwd: str, hashed_pwd: str) -> bool:
    return pwd_context.verify(plain_pwd, hashed_pwd)


def get_password_hash(pwd: str) -> str:
    return pwd_context.hash(pwd)


# JWT Handling
def create_access_token(
    subject: str | int,
    extra_claims: dict | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "access",
        "iat": datetime.now(timezone.utc),
    }

    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token() -> str:
    """Generate a cryptographically secure random token"""
    return secrets.token_urlsafe(64)


def hash_token(token: str) -> str:
    """Hash token for storage (if needed for lookups)."""
    return hashlib.sha256(token.encode()).hexdigest()


def decode_access_token(token: str) -> dict:
    """Decode and valiate access token"""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )

        if payload.get("type") != "access":
            raise JWTError("Invalid token type")
        return payload
    except JWTError as e:
        raise JWTError(f"Token validation failed: {e!s}")


# Redis Token Management
async def store_refresh_token(
    redis_client: redis.Redis, user_id: int, token: str
) -> None:
    """
    Store refresh token in Redis with automatice expiration.
    Key structure: refresh_token:{hashed_token}
    Value: JSON with user_id, created_at, is_revoked
    TTL: REFRESH_TOKEN_EXPIRE_DAYS
    """

    token_hash = hash_token(token)

    token_data = {
        "user_id": user_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_revoked": False,
    }

    # store with TTL(automatically deleted when expired)

    await redis_client.setex(
        f"refresh_token:{token_hash}",
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        json.dumps(token_data),
    )

    # Also maintain a set of users active refresh tokens for management

    await redis_client.sadd(f"user_tokens:{user_id}, token_hash")

    # Set the same TTL on the user tokens set
    await redis_client.expire(
        f"user_tokens:{user_id}", timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )


async def validate_refresh_token(redis_client: redis.Redis, token: str) -> dict | None:
    """
    Validate a refresh token and return its data if valid.
    Returns None if invalid, revoked, or expired.
    """

    token_hash = hash_token(token)
    token_key = f"refresh_token:{token_hash}"

    token_data_json = await redis_client.get(token_key)

    if not token_data_json:
        return None

    token_data = json.loads(token_data_json)

    if token_data.get("is_revoked"):
        return None

    return token_data


async def revoke_refresh_token(redis_client: redis.Redis, token: str) -> bool:
    """
    Revoke a specific refresh token.
    Returns True if successful, False if token not found.
    """

    token_hash = hash_token(token)
    token_key = f"refresh_token:{token_hash}"

    token_data_json = await redis_client.get(token_key)
    if not token_data_json:
        return False

    token_data = json.loads(token_data_json)
    token_data["is_revoked"] = True

    # Update the token with revoked status, keep the existing TTL
    ttl = await redis_client.ttl(token_key)
    if ttl > 0:
        await redis_client.setex(token_key, ttl, json.dumps(token_data))
    else:
        await redis_client.delete(token_key)

    return True

async def revoke_all_user_tokens(redis_client:redis.Redis, user_id:int) ->None:
    """Revoke all refresh tokens for a user(e.g on pwd change)"""
    #Get all token hashes for the user

    token_hashes = await redis_client.smembers(f"user_tokens:{user_id}")

    #Delete all individual tokens

    pipe = redis_client.pipeline()
    for token_hash in token_hashes:
        pipe.delete(f"refresh_token:{token_hash}")
    pipe.delete(f"user_tokens:{user_id}")
    await pipe.execute()


async def rotate_refresh_token(redis_client:redis.Redis, old_token:str, user_id:int) -> str | None:
    """
    Rotate refresh token: revoke old one and create new one.
    Returns new token, or None if old token is invalid.
    """

    if not await validate_refresh_token(redis_client, old_token):
        return None

    #Revoke old token

    await revoke_refresh_token(redis_client, old_token)

    #Create and store new token
    new_token = create_refresh_token()
    await store_refresh_token(redis_client, user_id, new_token)

    return new_token


# --- Session Cookie Helpers ---
from fastapi import Response


def set_session_cookie(response: Response, user_id: int):
    """Set a secure session cookie with a short-lived JWT."""

    token = create_access_token(subject=user_id, expires_delta=timedelta(seconds=settings.SESSION_COOKIE_MAX_AGE_SECONDS))

    response.set_cookie(
        key="session", value=token,max_age=settings.SESSION_COOKIE_MAX_AGE_SECONDS, httponly=True, secure=False, #For the time being, 
        samesite='lax', path='/'
    )




def clear_session_cookie(response: Response):
    """Clear the session cookie"""
    response.delete_cookie(key="session", path="/")
