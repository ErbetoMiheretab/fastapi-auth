from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"

    #Database

    DATABASE_URL: str = "postgresql+asyncpg://"

    # Redis
    REDIS_URL: str = "redis://localhost:6380/0"
    REDIS_PASSWORD: str | None = None

    #JWT

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_COOKIE_MAX_AGE_SECONDS: int = 3600  # 1 hour

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    
    # Security
    BCRYPT_ROUNDS: int = 12
    TRUSTED_PROXY_IPS: str = ""

    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }

settings =Settings()