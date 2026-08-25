from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR.parent / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    PROJECT_NAME: str = "Python RBAC API"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- RolesGuard / JWT decoding / Redis session tokens ---
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_SECRET_KEY: str = Field(
        default="change-me-to-a-long-random-string",
        validation_alias="SECRET_KEY",
    )
    JWT_ALGORITHM: str = "HS256"


settings = Settings()

