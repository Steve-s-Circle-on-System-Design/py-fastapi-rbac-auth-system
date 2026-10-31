from enum import StrEnum
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent


class BootstrapMode(StrEnum):
    """How the first admin is created on a fresh deployment."""

    OFF = "off"
    ENV = "env"
    HTTP = "http"


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

    # Base URL for verification links
    BASE_URL: str = "http://localhost:8000"

    @property
    def SECRET_KEY(self) -> str:
        return self.JWT_SECRET_KEY

    @property
    def ALGORITHM(self) -> str:
        return self.JWT_ALGORITHM

    # SMTP configuration dynamically read from .env
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "no-reply@example.com"
    SMTP_TLS: bool = False

    # Bootstrap admin (first admin on a fresh deployment)
    BOOTSTRAP_MODE: BootstrapMode = BootstrapMode.OFF
    BOOTSTRAP_ADMIN_EMAIL: str | None = None
    BOOTSTRAP_ADMIN_PASSWORD: str | None = None
    BOOTSTRAP_TOKEN: str | None = None


settings = Settings()
