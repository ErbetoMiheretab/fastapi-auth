from pydantic import BaseModel


class ValdiationError(BaseModel):
    loc: list[str]
    msg: str
    type: str


class HTTPValidationError(BaseModel):
    detail: list[ValdiationError]


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, any] | None = None


class APIError(BaseModel):
    error: ErrorDetail
    request_id: str | None = None
