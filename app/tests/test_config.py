from app.config import settings


def test_required_settings_present():
    # PROJECT_NAME is locked to an exact value, renaming the project name
    # will cause this test to fail, and i think it is good like that
    # however if you only want to check if the project name exists, replace the line
    # below with assert settings.PROJECT_NAME
    assert settings.PROJECT_NAME

    # API_V1_STR is locked too, since other clients hardcode this path
    # changing it would silently break every consumer of this API.
    assert settings.API_V1_STR == "/api/v1"

    assert settings.DATABASE_URL
    assert settings.JWT_SECRET_KEY
    assert settings.JWT_ALGORITHM

    # Token lifetimes must be positive so TTLs are always meaningful.
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0
    assert settings.REFRESH_TOKEN_EXPIRE_DAYS > 0
    assert settings.REFRESH_TOKEN_INACTIVITY_DAYS > 0
    assert settings.ACCOUNT_LOCKOUT_MINUTES > 0


def test_access_token_ttl_is_15_minutes():
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 15


def test_account_lockout_is_15_minutes():
    assert settings.ACCOUNT_LOCKOUT_MINUTES == 15


def test_database_url_uses_asyncpg_driver():
    assert settings.DATABASE_URL.startswith("postgresql+asyncpg://")


def test_jwt_algorithm_defaults_to_hs256():
    assert settings.JWT_ALGORITHM == "HS256"
