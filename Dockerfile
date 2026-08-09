# =============================================================================
# Stage 1: builder — install dependencies into an isolated venv
# =============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install system build deps (needed for asyncpg / cryptography C extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifest first for better layer caching
COPY req.txt .

# Create a virtual environment and install deps into it
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r req.txt


# =============================================================================
# Stage 2: runtime — lean image with only what is needed to run
# =============================================================================
FROM python:3.12-slim AS runtime

# Create a non-root user for security
RUN groupadd --gid 1001 appgroup && \
    useradd  --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# Pull system libs required at runtime (asyncpg needs libpq)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built virtualenv from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY src/ ./src/

# Set Python path so `src` package is importable without pip install
ENV PYTHONPATH="/app/src"

# Disable bytecode writes to keep the container FS clean; force unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Switch to non-root user
USER appuser

EXPOSE 8000

# Healthcheck — matches the /health endpoint added to main.py
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use uvicorn with uvloop for best async performance.
# Workers are intentionally set to 1 here; scale horizontally via replicas.
CMD ["uvicorn", "src.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--loop", "uvloop", \
     "--no-access-log"]
