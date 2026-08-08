from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from schemas.auth import UserCreate, UserLogin, TokenResponse, RefreshTokenRequest
from models.user import User
from core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    store_refresh_token,
    validate_refresh_token,
    revoke_refresh_token,
)
from api.deps import get_db, get_current_user
from core.redis import get_redis
import redis.asyncio as redis
import secrets

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    body: UserCreate,
    request: Request,
    response: Response,
    db: Annotated[
        AsyncSession,
        Dependes(get_db),
        redis_client : Annotated[redis.Redis, Depends(get_redis)],
    ],
):
    # Check existing user
    result = await db.execute(select(User).where(User.email == body.email))
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already registered"
        )

    # Create user
    user = User(
        email=body.email,
        hashed_password=get_password_hash(body.password),
        full_name=body.full_name,
    )

    db.add(user)

    await db.commit()
    await db.refresh(user)

    # Generate access token

    access_token = create_access_token(subject=user.id)

    # Genrate and store refresh token in Redis

    refresh_token_raw = create_refresh_token()
    await store_refresh_token(redis_client, user.id, refresh_token_raw)

    # Set session cookie for browser clients
    if "Mozilla" in request.headers.get("user-agent", ""):
        set_session_cookie(response, user.id)

    return TokenResponse(
        access_token=access_token, refresh_token=refresh_token_raw, token_type="bearer"
    )
