# OAuth + MFA (TOTP + Backup Codes) — Step-by-Step Implementation Guide

## Goal

Extend the existing FastAPI auth project with:
1. **MFA via TOTP** (authenticator apps: Google Authenticator, Authy, etc.)
2. **Backup codes** (10 single-use codes generated when enabling MFA)
3. **OAuth 2.0** (Google and GitHub social login)

The project currently has a solid foundation: async SQLAlchemy + PostgreSQL, Redis for token storage, JWT access tokens + opaque refresh tokens, and bcrypt password hashing.

---

## User Review Required

> [!IMPORTANT]
> **OAuth redirect URLs**: You must register your app in the Google Cloud Console and GitHub developer settings. The callback URLs will be:
> - Google: `http://localhost:8000/api/v1/oauth/google/callback`
> - GitHub: `http://localhost:8000/api/v1/oauth/github/callback`
> Update these when deploying to production.

> [!IMPORTANT]
> **TOTP secret encryption**: This plan stores TOTP secrets encrypted at rest with Fernet (symmetric encryption). This requires generating and securely storing a `TOTP_SECRET_ENCRYPTION_KEY`. If you prefer to skip encryption and store the raw base32 secret (simpler but less secure), let me know before proceeding.

> [!WARNING]
> **`src/api/deps.py` and `src/api/router.py` are currently empty** — the auth router at `src/api/v1/auth.py` imports functions from `security.py` that don't yet exist (`rotate_refresh_token`, `set_session_cookie`, etc.). These stubs are incomplete. This plan fills them in correctly.

> [!WARNING]
> **`main.py` is currently a standalone recursion challenge file** — it is not a FastAPI app. The plan includes creating `src/main.py` as the real FastAPI entrypoint.

---

## Open Questions

> [!IMPORTANT]
> 1. Do you want to support **account linking** — i.e., if a user already registered with email/password and then signs in with Google using the same email, do you want to auto-link the accounts?  
>    **Default in this plan: YES** — link by email.
>
> 2. Should OAuth users be able to **set a password later** (convert from OAuth-only to hybrid)? **Default: YES** via a separate endpoint.
>
> 3. Do you want **email verification** as part of the flow, or just trust the OAuth provider's verified email? **Default: Trust provider.**

---

## Proposed Changes

### Dependencies

#### [MODIFY] `pyproject.toml`

```toml
[project]
name = "fastapi-auth"
version = "0.1.0"
description = "FastAPI authentication service"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.30.0",
    "sqlalchemy>=2.0.0",
    "asyncpg>=0.29.0",
    "alembic>=1.13.0",
    "pydantic>=2.7.0",
    "pydantic-settings>=2.3.0",
    "python-jose[cryptography]>=3.3.0",
    "passlib[bcrypt]>=1.7.4",
    "redis>=5.0.0",
    # MFA
    "pyotp>=2.9.0",
    "qrcode[pil]>=7.4.0",
    "cryptography>=42.0.0",   # Fernet for TOTP secret encryption
    # OAuth
    "authlib>=1.3.0",
    "httpx>=0.27.0",
    "itsdangerous>=2.2.0",
]
```

**Install command:**
```bash
uv add pyotp "qrcode[pil]" cryptography authlib httpx itsdangerous
```

---

### Step 1 — Database Models

#### [MODIFY] `src/models/user.py`

Add MFA and OAuth columns to the `User` model. `hashed_password` becomes nullable to support OAuth-only users.

```diff
 import datetime
 import enum

-from sqlachemy import Boolean, Column, DateTime, Enum, Integer, String
+from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String
+from sqlalchemy.orm import relationship

 from core.db import Base


 class UserRole(str, enum.Enum):
     USER = "user"
     ADMIN = "admin"


 class User(Base):
     __tablename__ = "users"
     id             = Column(Integer, primary_key=True, index=True)
     email          = Column(String, unique=True, index=True, nullable=False)
-    hashed_password = Column(String, nullable=False)
+    hashed_password = Column(String, nullable=True)   # nullable for OAuth-only users
     full_name      = Column(String, nullable=True)
     role           = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
     is_active      = Column(Boolean, default=True)
     created_at     = Column(DateTime, default=datetime.datetime.utcnow)
+
+    # MFA
+    mfa_enabled       = Column(Boolean, default=False, nullable=False)
+    totp_secret       = Column(String, nullable=True)   # Fernet-encrypted base32 secret
+    mfa_verified_at   = Column(DateTime, nullable=True)
+
+    # OAuth
+    oauth_provider    = Column(String, nullable=True)   # "google" | "github" | None
+    oauth_id          = Column(String, nullable=True, index=True)
+    avatar_url        = Column(String, nullable=True)
+
+    # Relationships
+    backup_codes      = relationship("BackupCode", back_populates="user", lazy="select")
```

#### [NEW] `src/models/backup_code.py`

```python
import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from core.db import Base


class BackupCode(Base):
    """Single-use backup codes for MFA recovery."""

    __tablename__ = "backup_codes"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash  = Column(String, nullable=False)     # bcrypt hash of plain-text code
    used       = Column(Boolean, default=False, nullable=False)
    used_at    = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationship
    user = relationship("User", back_populates="backup_codes")
```

#### [NEW] `src/models/__init__.py`

```python
from .user import User, UserRole
from .backup_code import BackupCode

__all__ = ["BackupCode", "User", "UserRole"]
```

---

### Step 2 — Alembic Migrations

If Alembic is not yet initialized:
```bash
cd /home/dev1/fastapi-auth
uv run alembic init alembic
```

Update `alembic/env.py` to point at your models and DB:
```python
# In alembic/env.py
from src.models import User, BackupCode   # ensure models are imported so metadata is populated
from src.core.db import Base
from src.core.config import settings

target_metadata = Base.metadata

# In run_migrations_online(), use settings.DATABASE_URL
```

Generate and apply the migration:
```bash
uv run alembic revision --autogenerate -m "add_mfa_and_oauth_columns"
uv run alembic upgrade head
```

---

### Step 3 — Configuration

#### [MODIFY] `src/core/config.py`

```python
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str | None = None

    # JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_COOKIE_MAX_AGE_SECONDS: int = 3600

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # Security
    BCRYPT_ROUNDS: int = 12

    # MFA
    TOTP_SECRET_ENCRYPTION_KEY: str = ""     # Fernet key — see .env.example
    MFA_TOKEN_EXPIRE_MINUTES: int = 5        # Short-lived token for 2nd factor
    MFA_ISSUER_NAME: str = "FastAPI-Auth"
    BACKUP_CODE_COUNT: int = 10

    # OAuth — Google
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""

    # OAuth — GitHub
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""

    # OAuth shared
    OAUTH_REDIRECT_BASE_URL: str = "http://localhost:8000"

    class Config:
        env_file = ".env"


settings = Settings()
```

#### [MODIFY] `.env.example`

```env
# Database
DATABASE_URL=postgresql+asyncpg://auth_user:auth_pass@auth-db:5432/auth_db

# Redis
REDIS_URL=redis://:redispass@auth-redis:6379/0
REDIS_PASSWORD=redispass

# JWT
SECRET_KEY=your-super-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
SESSION_COOKIE_MAX_AGE_SECONDS=3600

# CORS
CORS_ORIGINS=["http://localhost:3000"]

# Security
BCRYPT_ROUNDS=12

# MFA
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
TOTP_SECRET_ENCRYPTION_KEY=
MFA_TOKEN_EXPIRE_MINUTES=5
MFA_ISSUER_NAME=FastAPI-Auth
BACKUP_CODE_COUNT=10

# OAuth — Google
# https://console.cloud.google.com → APIs & Services → Credentials
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# OAuth — GitHub
# https://github.com/settings/developers → New OAuth App
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

OAUTH_REDIRECT_BASE_URL=http://localhost:8000
```

---

### Step 4 — MFA Core Helpers

#### [NEW] `src/core/mfa.py`

```python
"""
MFA helper functions: TOTP generation/verification, backup code management,
and Fernet encryption/decryption of TOTP secrets at rest.
"""

import base64
import io
import secrets

import pyotp
import qrcode
from cryptography.fernet import Fernet
from passlib.context import CryptContext

from core.config import settings

# Separate context for backup codes (bcrypt)
_backup_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# TOTP Secret Encryption (Fernet symmetric)
# ---------------------------------------------------------------------------

def _get_fernet() -> Fernet:
    key = settings.TOTP_SECRET_ENCRYPTION_KEY
    if not key:
        raise RuntimeError("TOTP_SECRET_ENCRYPTION_KEY is not set")
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_totp_secret(plain_secret: str) -> str:
    """Encrypt a base32 TOTP secret before storing in the DB."""
    return _get_fernet().encrypt(plain_secret.encode()).decode()


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypt a stored TOTP secret."""
    return _get_fernet().decrypt(encrypted_secret.encode()).decode()


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Return a new random base32 secret (plain text)."""
    return pyotp.random_base32()


def get_totp_provisioning_uri(plain_secret: str, email: str) -> str:
    """Return the otpauth:// URI for QR code generation."""
    return pyotp.totp.TOTP(plain_secret).provisioning_uri(
        name=email,
        issuer_name=settings.MFA_ISSUER_NAME,
    )


def get_totp_qr_base64(provisioning_uri: str) -> str:
    """Generate a QR code PNG and return it as a base64 string."""
    img = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp_code(plain_secret: str, code: str) -> bool:
    """
    Verify a 6-digit TOTP code.
    valid_window=1 allows ±30s clock drift tolerance.
    """
    totp = pyotp.TOTP(plain_secret)
    return totp.verify(code, valid_window=1)


def get_current_totp_counter(plain_secret: str) -> int:
    """Return the current TOTP counter value (used for replay prevention)."""
    return pyotp.TOTP(plain_secret).timecode(pyotp.TOTP(plain_secret).now())


# ---------------------------------------------------------------------------
# Backup Codes
# ---------------------------------------------------------------------------

def generate_backup_codes(count: int | None = None) -> list[str]:
    """
    Generate `count` plain-text backup codes.
    Format: XXXX-XXXX (8 uppercase hex chars with a dash for readability).
    These are shown to the user ONCE and never stored in plain text.
    """
    n = count or settings.BACKUP_CODE_COUNT
    return [
        f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
        for _ in range(n)
    ]


def hash_backup_code(plain_code: str) -> str:
    """Hash a backup code for storage (bcrypt)."""
    # Normalize: strip dashes and uppercase before hashing
    normalized = plain_code.replace("-", "").upper()
    return _backup_ctx.hash(normalized)


def verify_backup_code(plain_code: str, hashed_code: str) -> bool:
    """Verify a backup code against its stored hash."""
    normalized = plain_code.replace("-", "").upper()
    return _backup_ctx.verify(normalized, hashed_code)
```

---

### Step 5 — Updated Security Module

#### [MODIFY] `src/core/security.py`

Add the missing functions that `auth.py` already imports, plus the MFA token helpers:

```python
# Add these functions to the existing security.py

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

import redis.asyncio as redis
from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---- existing functions (verify_password, get_password_hash, etc.) ----
# ... keep all existing code ...


# ---- NEW: MFA Token (short-lived, single-use) ----

def create_mfa_token(user_id: int) -> str:
    """
    Create a short-lived JWT used as an intermediate token during MFA.
    The client presents this token along with a TOTP/backup code.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.MFA_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "mfa",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_mfa_token(token: str) -> dict:
    """Decode and validate an MFA intermediate token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "mfa":
            raise JWTError("Invalid token type")
        return payload
    except JWTError as e:
        raise JWTError(f"MFA token validation failed: {e!s}")


# ---- NEW: Rotate refresh token (used by auth router) ----

async def rotate_refresh_token(
    redis_client: redis.Redis,
    user_id: int,
    old_token: str,
) -> str:
    """Revoke old refresh token and issue a new one (token rotation)."""
    await revoke_refresh_token(redis_client, old_token)
    new_token = create_refresh_token()
    await store_refresh_token(redis_client, user_id, new_token)
    return new_token


# ---- NEW: Revoke all user tokens ----

async def revoke_all_user_tokens(redis_client: redis.Redis, user_id: int) -> None:
    """Revoke all refresh tokens for a user (used on logout-all / password change)."""
    token_hashes = await redis_client.smembers(f"user_tokens:{user_id}")
    for token_hash in token_hashes:
        token_key = f"refresh_token:{token_hash}"
        data_json = await redis_client.get(token_key)
        if data_json:
            data = json.loads(data_json)
            data["is_revoked"] = True
            ttl = await redis_client.ttl(token_key)
            if ttl > 0:
                await redis_client.setex(token_key, ttl, json.dumps(data))
            else:
                await redis_client.delete(token_key)
    await redis_client.delete(f"user_tokens:{user_id}")


# ---- NEW: Cookie helpers ----

from fastapi import Response


def set_session_cookie(response: Response, refresh_token: str) -> None:
    """Set the refresh token as an HttpOnly cookie."""
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,          # Set False for local HTTP dev
        samesite="lax",
        max_age=settings.SESSION_COOKIE_MAX_AGE_SECONDS,
    )


def clear_session_cookie(response: Response) -> None:
    """Clear the refresh token cookie on logout."""
    response.delete_cookie(key="refresh_token", httponly=True, secure=True, samesite="lax")


# ---- NEW: TOTP Replay Prevention (Redis) ----

async def mark_totp_used(redis_client: redis.Redis, user_id: int, counter: int) -> bool:
    """
    Prevent TOTP code reuse within the same 30s window.
    Returns True if the counter is fresh (not yet used), False if replayed.
    """
    key = f"totp_used:{user_id}:{counter}"
    # SET NX with 90s TTL (covers ±1 window)
    result = await redis_client.set(key, "1", ex=90, nx=True)
    return result is not None  # None means key already existed → replay
```

---

### Step 6 — Schemas

#### [NEW] `src/schemas/mfa.py`

```python
from pydantic import BaseModel, Field


class MFASetupResponse(BaseModel):
    """Returned when a user initiates MFA setup."""
    secret: str           # Plain base32 secret — store in authenticator app
    qr_code_uri: str      # otpauth:// URI
    qr_image_b64: str     # Base64 PNG — display as <img src="data:image/png;base64,...">


class MFAVerifyRequest(BaseModel):
    """Confirm TOTP code to enable MFA."""
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class MFAEnableResponse(BaseModel):
    """Returned after MFA is successfully enabled."""
    msg: str = "MFA enabled successfully"
    backup_codes: list[str]   # Shown ONCE. User must save these.


class MFADisableRequest(BaseModel):
    """Disable MFA — requires current TOTP for verification."""
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class MFALoginRequest(BaseModel):
    """Complete login step 2 with a TOTP code."""
    mfa_token: str
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class MFABackupLoginRequest(BaseModel):
    """Complete login step 2 with a backup code."""
    mfa_token: str
    backup_code: str = Field(..., min_length=9, max_length=9)  # Format: XXXX-XXXX


class MFARequiredResponse(BaseModel):
    """Returned after password auth when MFA is enabled."""
    mfa_required: bool = True
    mfa_token: str   # Short-lived JWT; present this with TOTP/backup code


class BackupCodeRegenerateRequest(BaseModel):
    """Regenerate backup codes — requires current TOTP."""
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class BackupCodeRegenerateResponse(BaseModel):
    msg: str = "Backup codes regenerated"
    backup_codes: list[str]   # New codes — shown ONCE
```

#### [NEW] `src/schemas/oauth.py`

```python
from pydantic import BaseModel

from schemas.auth import TokenResponse
from schemas.mfa import MFARequiredResponse


class OAuthCallbackResult(BaseModel):
    """Internal result from the OAuth callback handler."""
    mfa_required: bool = False
    mfa_token: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
```

#### [MODIFY] `src/schemas/__init__.py`

```python
from .auth import (
    ErrorResponse,
    MessageResponse,
    RefreshTokenRequest,
    TokenResponse,
    UserLogin,
)
from .auth import UserCreate as AuthUserCreate
from .error import APIError, HTTPValidationError
from .mfa import (
    BackupCodeRegenerateRequest,
    BackupCodeRegenerateResponse,
    MFABackupLoginRequest,
    MFADisableRequest,
    MFAEnableResponse,
    MFALoginRequest,
    MFARequiredResponse,
    MFASetupResponse,
    MFAVerifyRequest,
)
from .oauth import OAuthCallbackResult
from .pagination import PaginatedResponse, PaginationParams
from .token import RefreshTokenData, TokenData, TokenPayload
from .user import UserList, UserOut, UserUpdate

__all__ = [
    "APIError",
    "AuthUserCreate",
    "BackupCodeRegenerateRequest",
    "BackupCodeRegenerateResponse",
    "ErrorResponse",
    "HTTPValidationError",
    "MFABackupLoginRequest",
    "MFADisableRequest",
    "MFAEnableResponse",
    "MFALoginRequest",
    "MFARequiredResponse",
    "MFASetupResponse",
    "MFAVerifyRequest",
    "MessageResponse",
    "OAuthCallbackResult",
    "PaginatedResponse",
    "PaginationParams",
    "RefreshTokenData",
    "RefreshTokenRequest",
    "TokenData",
    "TokenPayload",
    "TokenResponse",
    "UserList",
    "UserLogin",
    "UserOut",
    "UserUpdate",
]
```

---

### Step 7 — API Dependencies

#### [MODIFY] `src/api/deps.py`

```python
"""
FastAPI dependency functions shared across routers.
"""

from fastapi import Cookie, Depends, HTTPException, status
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.db import get_db
from core.redis import get_redis
from core.security import decode_access_token
from models.user import User
import redis.asyncio as redis


async def get_current_user(
    token: str | None = Cookie(None, alias="access_token"),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and validate JWT from the Authorization header or cookie,
    then return the corresponding User.
    
    NOTE: For Authorization header support, use:
        from fastapi.security import OAuth2PasswordBearer
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
    and add `token: str = Depends(oauth2_scheme)` instead.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except (JWTError, Exception):
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
```

---

### Step 8 — Services Layer

#### [NEW] `src/services/__init__.py`  _(empty)_

#### [NEW] `src/services/mfa_service.py`

```python
"""
MFA business logic: setup, enable, disable, verify, backup codes.
"""

import datetime

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

from core.mfa import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_backup_codes,
    generate_totp_secret,
    get_totp_provisioning_uri,
    get_totp_qr_base64,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)
from core.security import mark_totp_used
from models.backup_code import BackupCode
from models.user import User
from schemas.mfa import MFAEnableResponse, MFASetupResponse


async def setup_mfa(user: User) -> MFASetupResponse:
    """
    Generate a new TOTP secret for a user (not saved yet — only saved after verification).
    Returns the secret + QR code for the user to scan.
    """
    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    plain_secret = generate_totp_secret()
    uri = get_totp_provisioning_uri(plain_secret, user.email)
    qr_b64 = get_totp_qr_base64(uri)

    return MFASetupResponse(
        secret=plain_secret,
        qr_code_uri=uri,
        qr_image_b64=qr_b64,
    )


async def enable_mfa(
    user: User,
    totp_code: str,
    plain_secret: str,   # The secret returned in setup_mfa, sent back by client
    db: AsyncSession,
    redis_client: redis.Redis,
) -> MFAEnableResponse:
    """
    Verify the TOTP code against the provided secret, then enable MFA.
    Generates and returns backup codes (shown once).
    """
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA already enabled")

    if not verify_totp_code(plain_secret, totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    # Encrypt secret before persisting
    user.totp_secret = encrypt_totp_secret(plain_secret)
    user.mfa_enabled = True
    user.mfa_verified_at = datetime.datetime.utcnow()

    # Generate and persist backup codes
    plain_codes = generate_backup_codes()
    for code in plain_codes:
        db.add(BackupCode(user_id=user.id, code_hash=hash_backup_code(code)))

    await db.commit()
    await db.refresh(user)

    return MFAEnableResponse(backup_codes=plain_codes)


async def disable_mfa(
    user: User,
    totp_code: str,
    db: AsyncSession,
    redis_client: redis.Redis,
) -> None:
    """Disable MFA after verifying the current TOTP code."""
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    plain_secret = decrypt_totp_secret(user.totp_secret)
    if not verify_totp_code(plain_secret, totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    user.mfa_enabled = False
    user.totp_secret = None
    user.mfa_verified_at = None

    # Delete all backup codes
    await db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    await db.commit()


async def verify_totp_for_login(
    user: User,
    totp_code: str,
    redis_client: redis.Redis,
) -> bool:
    """
    Verify TOTP code for the login 2nd factor.
    Includes replay protection via Redis.
    Returns True if valid.
    """
    if not user.mfa_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="MFA not enabled for this user")

    plain_secret = decrypt_totp_secret(user.totp_secret)

    if not verify_totp_code(plain_secret, totp_code):
        raise HTTPException(status_code=400, detail="Invalid or expired TOTP code")

    # Replay protection
    import pyotp
    counter = pyotp.TOTP(plain_secret).timecode(pyotp.TOTP(plain_secret).now())
    fresh = await mark_totp_used(redis_client, user.id, counter)
    if not fresh:
        raise HTTPException(status_code=400, detail="TOTP code already used")

    return True


async def verify_backup_code_for_login(
    user: User,
    plain_code: str,
    db: AsyncSession,
) -> bool:
    """
    Verify a backup code for login. Marks it as used.
    Returns True if valid.
    """
    result = await db.execute(
        select(BackupCode).where(
            BackupCode.user_id == user.id,
            BackupCode.used == False,  # noqa: E712
        )
    )
    unused_codes = result.scalars().all()

    for backup_code in unused_codes:
        if verify_backup_code(plain_code, backup_code.code_hash):
            backup_code.used = True
            backup_code.used_at = datetime.datetime.utcnow()
            await db.commit()
            return True

    raise HTTPException(status_code=400, detail="Invalid or already-used backup code")


async def regenerate_backup_codes(
    user: User,
    totp_code: str,
    db: AsyncSession,
    redis_client: redis.Redis,
) -> list[str]:
    """Invalidate all existing backup codes and generate new ones."""
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    # Verify identity with TOTP
    await verify_totp_for_login(user, totp_code, redis_client)

    # Delete old codes
    await db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))

    # Generate new codes
    plain_codes = generate_backup_codes()
    for code in plain_codes:
        db.add(BackupCode(user_id=user.id, code_hash=hash_backup_code(code)))

    await db.commit()
    return plain_codes
```

#### [NEW] `src/services/oauth_service.py`

```python
"""
OAuth 2.0 service: user lookup, account creation, and provider-specific user info.
"""

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.user import User, UserRole


async def get_or_create_oauth_user(
    db: AsyncSession,
    *,
    provider: str,
    oauth_id: str,
    email: str,
    full_name: str | None = None,
    avatar_url: str | None = None,
) -> User:
    """
    1. Try to find a user by oauth_id + provider.
    2. If not found, try to find by email (link existing account).
    3. If not found, create a new OAuth-only user.
    """
    # 1. Exact match by provider + oauth_id
    result = await db.execute(
        select(User).where(User.oauth_provider == provider, User.oauth_id == oauth_id)
    )
    user = result.scalar_one_or_none()
    if user:
        return user

    # 2. Link by email
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user:
        user.oauth_provider = provider
        user.oauth_id = oauth_id
        if avatar_url and not user.avatar_url:
            user.avatar_url = avatar_url
        await db.commit()
        await db.refresh(user)
        return user

    # 3. Create new OAuth-only user
    user = User(
        email=email,
        full_name=full_name,
        avatar_url=avatar_url,
        hashed_password=None,      # No password for OAuth-only users
        oauth_provider=provider,
        oauth_id=oauth_id,
        role=UserRole.USER,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def fetch_google_user_info(access_token: str) -> dict:
    """Fetch user info from Google's userinfo endpoint."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


async def fetch_github_user_info(access_token: str) -> dict:
    """Fetch user info from GitHub API."""
    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        user_resp.raise_for_status()
        user_data = user_resp.json()

        # GitHub may not expose email if set to private — fetch separately
        if not user_data.get("email"):
            emails_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            emails_resp.raise_for_status()
            emails = emails_resp.json()
            primary = next(
                (e["email"] for e in emails if e.get("primary") and e.get("verified")),
                None,
            )
            user_data["email"] = primary

        return user_data
```

---

### Step 9 — Updated Auth Router

#### [MODIFY] `src/api/v1/auth.py`

Complete the router with all endpoints including the MFA 2nd-step login:

```python
"""
Authentication endpoints: register, login, refresh, logout, MFA 2nd factor.
"""

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

from api.deps import get_current_user
from core.db import get_db
from core.redis import get_redis
from core.security import (
    clear_session_cookie,
    create_access_token,
    create_mfa_token,
    create_refresh_token,
    decode_mfa_token,
    get_password_hash,
    revoke_all_user_tokens,
    revoke_refresh_token,
    rotate_refresh_token,
    set_session_cookie,
    store_refresh_token,
    validate_refresh_token,
    verify_password,
)
from models.user import User
from schemas.auth import (
    MessageResponse,
    RefreshTokenRequest,
    TokenResponse,
    UserCreate,
    UserLogin,
)
from schemas.mfa import (
    MFABackupLoginRequest,
    MFALoginRequest,
    MFARequiredResponse,
)
from services.mfa_service import verify_backup_code_for_login, verify_totp_for_login

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user with email and password."""
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    await db.commit()
    return MessageResponse(msg="User registered successfully")


@router.post("/login")
async def login(
    payload: UserLogin,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """
    Step 1 of login.
    - If MFA is disabled: returns {access_token, refresh_token}.
    - If MFA is enabled: returns {mfa_required: true, mfa_token}.
    """
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not user.hashed_password or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account is inactive")

    # MFA required — return intermediate token
    if user.mfa_enabled:
        mfa_token = create_mfa_token(user.id)
        return MFARequiredResponse(mfa_token=mfa_token)

    # No MFA — issue tokens directly
    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token()
    await store_refresh_token(redis_client, user.id, refresh_token)
    set_session_cookie(response, refresh_token)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/mfa/verify", response_model=TokenResponse)
async def mfa_verify_totp(
    payload: MFALoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Step 2 of login — verify TOTP code."""
    try:
        token_data = decode_mfa_token(payload.mfa_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    user_id = int(token_data["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    await verify_totp_for_login(user, payload.totp_code, redis_client)

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token()
    await store_refresh_token(redis_client, user.id, refresh_token)
    set_session_cookie(response, refresh_token)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/mfa/backup", response_model=TokenResponse)
async def mfa_verify_backup_code(
    payload: MFABackupLoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Step 2 of login — verify a backup code."""
    try:
        token_data = decode_mfa_token(payload.mfa_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    user_id = int(token_data["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    await verify_backup_code_for_login(user, payload.backup_code, db)

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token()
    await store_refresh_token(redis_client, user.id, refresh_token)
    set_session_cookie(response, refresh_token)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    payload: RefreshTokenRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Exchange a valid refresh token for a new access + refresh token pair."""
    token_data = await validate_refresh_token(redis_client, payload.refresh_token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user_id = token_data["user_id"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    new_refresh = await rotate_refresh_token(redis_client, user_id, payload.refresh_token)
    access_token = create_access_token(subject=user_id)
    set_session_cookie(response, new_refresh)

    return TokenResponse(access_token=access_token, refresh_token=new_refresh)


@router.post("/logout", response_model=MessageResponse)
async def logout(
    response: Response,
    payload: RefreshTokenRequest,
    redis_client: redis.Redis = Depends(get_redis),
):
    """Revoke the current refresh token and clear the session cookie."""
    await revoke_refresh_token(redis_client, payload.refresh_token)
    clear_session_cookie(response)
    return MessageResponse(msg="Logged out successfully")


@router.post("/logout-all", response_model=MessageResponse)
async def logout_all(
    response: Response,
    current_user: User = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Revoke ALL refresh tokens for the current user (all devices)."""
    await revoke_all_user_tokens(redis_client, current_user.id)
    clear_session_cookie(response)
    return MessageResponse(msg="Logged out from all devices")
```

---

### Step 10 — MFA Endpoints

#### [NEW] `src/api/v1/mfa.py`

```python
"""
MFA management endpoints: setup, enable, disable, regenerate backup codes.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

from api.deps import get_current_user
from core.db import get_db
from core.redis import get_redis
from models.user import User
from schemas.auth import MessageResponse
from schemas.mfa import (
    BackupCodeRegenerateRequest,
    BackupCodeRegenerateResponse,
    MFADisableRequest,
    MFAEnableResponse,
    MFASetupResponse,
    MFAVerifyRequest,
)
from services.mfa_service import (
    disable_mfa,
    enable_mfa,
    regenerate_backup_codes,
    setup_mfa,
)

router = APIRouter(prefix="/mfa", tags=["MFA"])


@router.post("/setup", response_model=MFASetupResponse)
async def mfa_setup(current_user: User = Depends(get_current_user)):
    """
    Generate a TOTP secret and QR code.
    The user must scan this with their authenticator app,
    then confirm with POST /mfa/verify to actually enable MFA.
    """
    return await setup_mfa(current_user)


@router.post("/verify", response_model=MFAEnableResponse)
async def mfa_enable(
    payload: MFAVerifyRequest,
    # The plain secret from the setup step, passed back by the client
    # In production you'd want to cache this in Redis keyed by user session
    # For simplicity here we accept it in the request body
    plain_secret: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """
    Confirm TOTP code to enable MFA. Returns backup codes (shown once — save them!).
    
    NOTE: The `plain_secret` should be the value returned from POST /mfa/setup.
    A more secure approach caches it server-side (Redis, keyed by user+session).
    """
    return await enable_mfa(
        user=current_user,
        totp_code=payload.totp_code,
        plain_secret=plain_secret,
        db=db,
        redis_client=redis_client,
    )


@router.post("/disable", response_model=MessageResponse)
async def mfa_disable(
    payload: MFADisableRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Disable MFA. Requires a valid TOTP code to confirm identity."""
    await disable_mfa(
        user=current_user,
        totp_code=payload.totp_code,
        db=db,
        redis_client=redis_client,
    )
    return MessageResponse(msg="MFA disabled successfully")


@router.post("/backup-codes/regenerate", response_model=BackupCodeRegenerateResponse)
async def regenerate_codes(
    payload: BackupCodeRegenerateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """
    Regenerate backup codes. Old codes are immediately invalidated.
    Requires a valid TOTP code.
    """
    new_codes = await regenerate_backup_codes(
        user=current_user,
        totp_code=payload.totp_code,
        db=db,
        redis_client=redis_client,
    )
    return BackupCodeRegenerateResponse(backup_codes=new_codes)
```

---

### Step 11 — OAuth Endpoints

#### [NEW] `src/api/v1/oauth.py`

```python
"""
OAuth 2.0 endpoints: Google and GitHub social login.
"""

import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

from core.config import settings
from core.db import get_db
from core.redis import get_redis
from core.security import (
    create_access_token,
    create_mfa_token,
    create_refresh_token,
    set_session_cookie,
    store_refresh_token,
)
from schemas.auth import TokenResponse
from schemas.mfa import MFARequiredResponse
from services.oauth_service import (
    fetch_github_user_info,
    fetch_google_user_info,
    get_or_create_oauth_user,
)

router = APIRouter(prefix="/oauth", tags=["OAuth"])

# ---------------------------------------------------------------------------
# Google
# ---------------------------------------------------------------------------

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


@router.get("/google/authorize")
async def google_authorize(redis_client: redis.Redis = Depends(get_redis)):
    """Redirect the user to Google's OAuth consent screen."""
    state = secrets.token_urlsafe(32)
    # Store state in Redis (10 min TTL) for CSRF validation
    await redis_client.setex(f"oauth_state:{state}", 600, "google")

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": f"{settings.OAUTH_REDIRECT_BASE_URL}/api/v1/oauth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    return {"authorization_url": f"{GOOGLE_AUTH_URL}?{urlencode(params)}"}


@router.get("/google/callback")
async def google_callback(
    code: str,
    state: str,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Handle Google's callback: exchange code, fetch user, issue tokens."""
    # Validate CSRF state
    stored = await redis_client.get(f"oauth_state:{state}")
    if not stored or stored != "google":
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    await redis_client.delete(f"oauth_state:{state}")

    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": f"{settings.OAUTH_REDIRECT_BASE_URL}/api/v1/oauth/google/callback",
                "grant_type": "authorization_code",
            },
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

    user_info = await fetch_google_user_info(tokens["access_token"])

    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Could not get email from Google")

    user = await get_or_create_oauth_user(
        db,
        provider="google",
        oauth_id=user_info["sub"],
        email=email,
        full_name=user_info.get("name"),
        avatar_url=user_info.get("picture"),
    )

    if user.mfa_enabled:
        return MFARequiredResponse(mfa_token=create_mfa_token(user.id))

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token()
    await store_refresh_token(redis_client, user.id, refresh_token)
    set_session_cookie(response, refresh_token)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"


@router.get("/github/authorize")
async def github_authorize(redis_client: redis.Redis = Depends(get_redis)):
    """Redirect the user to GitHub's OAuth consent screen."""
    state = secrets.token_urlsafe(32)
    await redis_client.setex(f"oauth_state:{state}", 600, "github")

    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": f"{settings.OAUTH_REDIRECT_BASE_URL}/api/v1/oauth/github/callback",
        "scope": "user:email",
        "state": state,
    }
    return {"authorization_url": f"{GITHUB_AUTH_URL}?{urlencode(params)}"}


@router.get("/github/callback")
async def github_callback(
    code: str,
    state: str,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Handle GitHub's callback: exchange code, fetch user, issue tokens."""
    stored = await redis_client.get(f"oauth_state:{state}")
    if not stored or stored != "github":
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    await redis_client.delete(f"oauth_state:{state}")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "redirect_uri": f"{settings.OAUTH_REDIRECT_BASE_URL}/api/v1/oauth/github/callback",
            },
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

    access_token = tokens.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Failed to get GitHub access token")

    user_info = await fetch_github_user_info(access_token)
    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Could not get email from GitHub")

    user = await get_or_create_oauth_user(
        db,
        provider="github",
        oauth_id=str(user_info["id"]),
        email=email,
        full_name=user_info.get("name"),
        avatar_url=user_info.get("avatar_url"),
    )

    if user.mfa_enabled:
        return MFARequiredResponse(mfa_token=create_mfa_token(user.id))

    access_token_jwt = create_access_token(subject=user.id)
    refresh_token = create_refresh_token()
    await store_refresh_token(redis_client, user.id, refresh_token)
    set_session_cookie(response, refresh_token)

    return TokenResponse(access_token=access_token_jwt, refresh_token=refresh_token)
```

---

### Step 12 — API Router

#### [MODIFY] `src/api/router.py`

```python
from fastapi import APIRouter

from api.v1 import auth, mfa, oauth

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(mfa.router)
api_router.include_router(oauth.router)
```

---

### Step 13 — FastAPI Application Entry Point

#### [NEW] `src/main.py`

```python
"""
FastAPI application entry point.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.router import api_router
from core.config import settings
from core.redis import check_redis_connection


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await check_redis_connection()
    yield
    # Shutdown — cleanup if needed


app = FastAPI(
    title="FastAPI Auth Service",
    description="Authentication service with JWT, OAuth, and MFA",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health")
async def health():
    return {"status": "ok"}
```

---

### Step 14 — Update Test Conftest

#### [MODIFY] `tests/conftest.py`

Add fixtures for MFA-enabled users and OAuth users:

```python
# Add to the existing conftest.py

from src.models.backup_code import BackupCode
from src.core.mfa import (
    generate_totp_secret,
    encrypt_totp_secret,
    generate_backup_codes,
    hash_backup_code,
)

@pytest.fixture
async def test_user_with_mfa(db_session: AsyncSession) -> tuple[User, str]:
    """Create a user with MFA enabled. Returns (user, plain_totp_secret)."""
    plain_secret = generate_totp_secret()
    user = User(
        email="mfa@example.com",
        hashed_password=get_password_hash("MFAPass123!"),
        full_name="MFA User",
        role=UserRole.USER,
        is_active=True,
        mfa_enabled=True,
        totp_secret=encrypt_totp_secret(plain_secret),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # Create backup codes
    plain_codes = generate_backup_codes(count=10)
    for code in plain_codes:
        db_session.add(BackupCode(user_id=user.id, code_hash=hash_backup_code(code)))
    await db_session.commit()

    return user, plain_secret, plain_codes


@pytest.fixture
async def test_oauth_user(db_session: AsyncSession) -> User:
    """Create an OAuth-only user (no password)."""
    user = User(
        email="oauth@example.com",
        hashed_password=None,
        full_name="OAuth User",
        role=UserRole.USER,
        is_active=True,
        oauth_provider="google",
        oauth_id="google-sub-12345",
        avatar_url="https://example.com/avatar.png",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user
```

#### [NEW] `tests/unit/test_mfa.py`

```python
import pytest
import pyotp
from core.mfa import (
    generate_totp_secret,
    verify_totp_code,
    generate_backup_codes,
    hash_backup_code,
    verify_backup_code,
    encrypt_totp_secret,
    decrypt_totp_secret,
)


def test_totp_generates_valid_secret():
    secret = generate_totp_secret()
    assert len(secret) == 32  # pyotp default is 32-char base32


def test_totp_verify_correct_code():
    secret = generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert verify_totp_code(secret, code) is True


def test_totp_verify_wrong_code():
    secret = generate_totp_secret()
    assert verify_totp_code(secret, "000000") is False


def test_backup_code_generation():
    codes = generate_backup_codes(10)
    assert len(codes) == 10
    for code in codes:
        assert len(code) == 9   # "XXXX-XXXX"
        assert "-" in code


def test_backup_code_hash_and_verify():
    codes = generate_backup_codes(5)
    for code in codes:
        hashed = hash_backup_code(code)
        assert verify_backup_code(code, hashed) is True
        assert verify_backup_code("WRONG-CODE", hashed) is False


def test_backup_code_normalization():
    """Lowercase and no-dash versions should verify successfully."""
    code = "ABCD-EF01"
    hashed = hash_backup_code(code)
    assert verify_backup_code("abcd-ef01", hashed) is True
    assert verify_backup_code("ABCDEF01", hashed) is True


def test_totp_secret_encryption_roundtrip(monkeypatch):
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode()
    monkeypatch.setattr("core.config.settings.TOTP_SECRET_ENCRYPTION_KEY", key)

    secret = generate_totp_secret()
    encrypted = encrypt_totp_secret(secret)
    assert encrypted != secret
    assert decrypt_totp_secret(encrypted) == secret
```

---

## Full Auth Flow Diagrams

### Login + MFA TOTP

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant DB as PostgreSQL
    participant R as Redis

    C->>A: POST /auth/login {email, password}
    A->>DB: SELECT user WHERE email=...
    DB-->>A: User record
    A->>A: verify_password()
    
    alt Password invalid
        A-->>C: 401 Invalid credentials
    else MFA disabled
        A->>R: store_refresh_token()
        A-->>C: 200 {access_token, refresh_token}
    else MFA enabled
        A->>A: create_mfa_token() [5min JWT]
        A-->>C: 200 {mfa_required: true, mfa_token}
        C->>A: POST /auth/mfa/verify {mfa_token, totp_code}
        A->>A: decode_mfa_token()
        A->>DB: SELECT user WHERE id=...
        A->>A: verify_totp_code() + replay check in Redis
        A->>R: store_refresh_token()
        A-->>C: 200 {access_token, refresh_token}
    end
```

### OAuth Flow (Google)

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant G as Google
    participant DB as PostgreSQL
    participant R as Redis

    C->>A: GET /oauth/google/authorize
    A->>R: SET oauth_state:{state} "google" EX 600
    A-->>C: {authorization_url: "https://accounts.google.com/..."}
    C->>G: Redirect + user grants consent
    G->>A: GET /oauth/google/callback?code=...&state=...
    A->>R: GET oauth_state:{state} → validate + DELETE
    A->>G: POST token exchange
    G-->>A: {access_token}
    A->>G: GET /userinfo
    G-->>A: {sub, email, name, picture}
    A->>DB: Upsert user (oauth_id match → email match → create)
    alt MFA enabled
        A-->>C: {mfa_required: true, mfa_token}
    else
        A->>R: store_refresh_token()
        A-->>C: {access_token, refresh_token}
    end
```

### MFA Setup Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant DB as PostgreSQL

    C->>A: POST /mfa/setup [authenticated]
    A->>A: generate_totp_secret() — plain base32
    A-->>C: {secret, qr_code_uri, qr_image_b64}
    Note over C: User scans QR in authenticator app
    C->>A: POST /mfa/verify {totp_code, plain_secret}
    A->>A: verify_totp_code(plain_secret, totp_code)
    A->>A: encrypt_totp_secret(plain_secret)
    A->>DB: UPDATE user SET mfa_enabled=true, totp_secret=encrypted
    A->>DB: INSERT 10 × BackupCode (bcrypt hashed)
    A-->>C: {msg, backup_codes: [...]}
    Note over C: User saves backup codes — shown ONCE
```

---

## Verification Plan

### Automated Tests

```bash
# Run all tests
cd /home/dev1/fastapi-auth
uv run pytest tests/ -v

# Run only MFA unit tests
uv run pytest tests/unit/test_mfa.py -v

# Run with coverage
uv run pytest tests/ --cov=src --cov-report=term-missing
```

### Manual Verification Checklist

1. **MFA Setup**
   - `POST /api/v1/mfa/setup` while authenticated → should return `qr_image_b64`
   - Scan QR in Google Authenticator or Authy
   - `POST /api/v1/mfa/verify` with correct 6-digit code → MFA enabled, backup codes returned
   - Try verifying with an invalid code → should return `400`

2. **MFA Login**
   - `POST /api/v1/auth/login` with MFA-enabled account → should return `{mfa_required: true, mfa_token}`
   - `POST /api/v1/auth/mfa/verify` with correct TOTP → full tokens returned
   - Reuse the same TOTP code immediately → should return `400` (replay protection)
   - `POST /api/v1/auth/mfa/backup` with a valid backup code → full tokens returned
   - Reuse that backup code → should return `400`

3. **OAuth — Google**
   - `GET /api/v1/oauth/google/authorize` → returns Google URL
   - Complete OAuth flow in browser → redirects to callback → tokens returned
   - Try with an already-existing email-password user → account should be linked

4. **Backup Code Regeneration**
   - `POST /api/v1/mfa/backup-codes/regenerate` with valid TOTP → new codes returned, old codes rejected

5. **MFA Disable**
   - `POST /api/v1/mfa/disable` with valid TOTP → MFA disabled, login no longer requires 2nd factor

---

## Implementation Checklist

- [ ] `uv add pyotp "qrcode[pil]" cryptography authlib httpx itsdangerous`
- [ ] Update `src/models/user.py` (MFA + OAuth columns)
- [ ] Create `src/models/backup_code.py`
- [ ] Create `src/models/__init__.py`
- [ ] Run Alembic migration
- [ ] Update `src/core/config.py`
- [ ] Update `.env.example` (and your local `.env`)
- [ ] Generate Fernet key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- [ ] Create `src/core/mfa.py`
- [ ] Update `src/core/security.py` (add missing functions)
- [ ] Create `src/schemas/mfa.py`
- [ ] Create `src/schemas/oauth.py`
- [ ] Update `src/schemas/__init__.py`
- [ ] Fill `src/api/deps.py`
- [ ] Create `src/services/__init__.py`
- [ ] Create `src/services/mfa_service.py`
- [ ] Create `src/services/oauth_service.py`
- [ ] Update `src/api/v1/auth.py`
- [ ] Create `src/api/v1/mfa.py`
- [ ] Create `src/api/v1/oauth.py`
- [ ] Update `src/api/router.py`
- [ ] Create `src/main.py`
- [ ] Update `tests/conftest.py`
- [ ] Create `tests/unit/test_mfa.py`
- [ ] Register OAuth apps with Google and GitHub
