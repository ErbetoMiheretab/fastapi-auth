from datetime import datetime

from pydantic import BaseModel


class TokenPayload(BaseModel):
    sub: str
    exp: datetime
    type: str = "access"
    iat: datetime | None = None


class TokenData(BaseModel):
    user_id: int
    token_type: str


class RefreshTokenData(BaseModel):
    user_id: int
    created_at: datetime
    is_revoked: bool = False
