from app.config import settings


def test_settings_load_from_app_env():
    assert settings.PROJECT_NAME == "Python RBAC API"
    assert settings.API_V1_STR == "/api/v1"
    assert "postgresql+asyncpg://" in settings.DATABASE_URL
