from pathlib import Path

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
    # --- Added for RolesGuard / JWT decoding ---
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_SECRET_KEY: str = "secret-key-for-jwt-signing"
    JWT_ALGORITHM: str = "HS256"

    @property
    def SECRET_KEY(self) -> str:
        return self.JWT_SECRET_KEY

    @property
    def ALGORITHM(self) -> str:
        return self.JWT_ALGORITHM

    # SMTP configuration
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "no-reply@example.com"


settings = Settings()
