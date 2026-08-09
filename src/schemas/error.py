from typing import Any

from pydantic import BaseModel


class ValidationError(BaseModel):
    loc: list[str]
    msg: str
    type: str


class HTTPValidationError(BaseModel):
    detail: list[ValidationError]


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class APIError(BaseModel):
    error: ErrorDetail
    request_id: str | None = None
