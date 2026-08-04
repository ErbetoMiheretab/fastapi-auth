from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    #Database

    DATABASE_URL: str = "postgresql+asyncpg://"

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

    class Config:
        env_file = ".env"

settings =Settings()