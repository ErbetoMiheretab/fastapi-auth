from fastapi import Query
from pydantic import BaseModel


class paginationParams:
    """Pagination parameters for dependency injection."""

    def __init__(
        self,
        page: int = Query(1, ge=1, description="Page number"),
        size: int = Query(20, ge=1, le=100, description="Items per page"),
    ):
        self.page = page
        self.size = size
        self.offset = (page - 1) * size


class PaginatedResponse[T](BaseModel):
    """Generic paginated response."""

    items: list[T]
    total: int
    page: int
    size: int
    pages: int

    @classmethod
    def create(cls, items: list[T], total: int, page: int, size: int):
        pages = total + size - 1

        return cls(items=items, total=total, page=page, size=size, pages=pages)
