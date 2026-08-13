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
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    # --- Token lifetimes ---
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REFRESH_TOKEN_INACTIVITY_DAYS: int = 3
    # --- Account lockout ---
    ACCOUNT_LOCKOUT_MINUTES: int = 15


settings = Settings()  # type: ignore[call-arg]
