import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.router import api_router
from core.config import settings
from core.db import Base, engine
from core.redis import check_redis_connection
from middleware import (
    AuthRateLimitMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Modern Lifespan Manager (replaces @app.on_event)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup Logic ---
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    await check_redis_connection()
    logger.info("Auth microservice started successfully with all middleware")
    
    yield  # Application runs here
    
    # --- Shutdown Logic ---
    await engine.dispose()
    logger.info("Auth microservice shutdown")


app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ==============================================================================
# Middleware Stack Configuration (Execution Order: Top to Bottom)
# Note: Declarations are added in REVERSE order due to Starlette's LIFO stack.
# ==============================================================================

# Execution Step 5: Innermost layer (runs right before routing to API endpoints)
app.add_middleware(
    AuthRateLimitMiddleware,
    max_attempts=5,
    window_seconds=300,
    lockout_seconds=900,
)

# Execution Step 4: General API rate limiting
app.add_middleware(
    RateLimitMiddleware,
    max_requests=100,
    window_seconds=60,
    excluded_paths=["/health", "/docs", "/redoc", "/openapi.json"],
)

# Execution Step 3: Request logging (captures application execution time)
app.add_middleware(RequestLoggingMiddleware)

# Execution Step 2: Security Headers
app.add_middleware(SecurityHeadersMiddleware)

# Execution Step 1: CORS (Outermost layer - guarantees headers on ALL responses)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Process-Time", "Retry-After"],
)

# Include versioned API
app.include_router(api_router)

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}
