from typing import Annotated

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db
from core.redis import get_redis
from core.security import (
    clear_session_cookie,
    create_access_token,
    create_refresh_token,
    get_password_hash,
    revoke_refresh_token,
    rotate_refresh_token,
    set_session_cookie,
    store_refresh_token,
    validate_refresh_token,
    verify_password,
)
from models.user import User
from schemas.auth import RefreshTokenRequest, TokenResponse, UserCreate, UserLogin

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    body: UserCreate,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis_client: Annotated[redis.Redis, Depends(get_redis)],
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


@router.post("/login", response_model=TokenResponse)
async def login(
    body: UserLogin,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    redis_client: Annotated[redis.Redis, Depends(get_redis)],
):
    #Find User
    result= await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )

    #Generate tokens

    access_token = create_access_token(subject=user.id)

    refresh_token_raw = create_refresh_token()

    await store_refresh_token(redis_client, user.id, refresh_token_raw)

     # Set session cookie for browser clients
    if "Mozilla" in request.headers.get("user-agent", ""):
        set_session_cookie(response, user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_raw,
        token_type="bearer"
    )



@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    body: RefreshTokenRequest,
    request: Request,
    response: Response,
    redis_client: Annotated[redis.Redis, Depends(get_redis)],
):
    #Rotate the refresh token
    token_data = await validate_refresh_token(redis_client, body.refresh_token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or expired refresh token"
        )

    user_id = token_data["user_id"]

    new_refresh_token = await rotate_refresh_token(redis_client, body.refresh_token, user_id)

    #create a new access token

    access_token = create_access_token(subject=user_id)


    # Set session cookie for browser clients
    if "Mozilla" in request.headers.get("user-agent", ""):
        set_session_cookie(response, user_id)


    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token, token_type="bearer")

@router.post("/logout")
async def logout(
    redis_client: Annotated[redis.Redis, Depends(get_redis)],
    current_user: Annotated[User, Depends(get_current_user)],
    refresh_token_body: RefreshTokenRequest | None = None,
    response: Response = None,
):
    # Revoke specific refresh token if provided
    if refresh_token_body:
        await revoke_refresh_token(redis_client, refresh_token_body.refresh_token)
    
    # Optionally revoke all tokens for this user (for security)
    # await revoke_all_user_tokens(redis_client, current_user.id)
    
    # Clear session cookie
    clear_session_cookie(response)
    
    return {"msg": "Successfully logged out"}