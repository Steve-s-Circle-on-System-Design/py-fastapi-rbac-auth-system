"""Bootstrap admin: env mode, http mode, and the failure modes."""

import pytest
from sqlalchemy import delete, func, select

from app.auth import create_new_user
from app.bootstrap import bootstrap_from_env, validate_http_bootstrap
from app.config import BootstrapMode, settings
from app.contracts import UserCreate
from app.models import Role as DbRole, User, UserRole

BOOTSTRAP_URL = f"{settings.API_V1_STR}/bootstrap"


async def _admin_count(db) -> int:
    return await db.scalar(
        select(func.count())
        .select_from(UserRole)
        .join(DbRole, DbRole.id == UserRole.role_id)
        .where(DbRole.name == "ADMIN")
    )


def _use_env_mode(monkeypatch, email="admin@example.com", password="s3cret!"):
    monkeypatch.setattr(settings, "BOOTSTRAP_MODE", BootstrapMode.ENV)
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_EMAIL", email)
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_PASSWORD", password)


def _use_http_mode(monkeypatch, token="test-bootstrap-token"):
    monkeypatch.setattr(settings, "BOOTSTRAP_MODE", BootstrapMode.HTTP)
    monkeypatch.setattr(settings, "BOOTSTRAP_TOKEN", token)


@pytest.mark.asyncio
async def test_env_mode_creates_one_verified_admin(db_session, monkeypatch):
    _use_env_mode(monkeypatch)

    await bootstrap_from_env(db_session)

    user = await db_session.scalar(
        select(User).where(User.email == "admin@example.com")
    )
    assert user is not None
    assert user.is_verified is True
    assert user.email_verified_at is not None
    assert await _admin_count(db_session) == 1

    role_names = (
        await db_session.scalars(
            select(DbRole.name)
            .join(UserRole, UserRole.role_id == DbRole.id)
            .where(UserRole.user_id == user.id)
        )
    ).all()
    assert set(role_names) == {"ADMIN"}


@pytest.mark.asyncio
async def test_env_mode_is_idempotent(db_session, monkeypatch):
    _use_env_mode(monkeypatch)

    await bootstrap_from_env(db_session)
    await bootstrap_from_env(db_session)

    assert await _admin_count(db_session) == 1
    assert await db_session.scalar(select(func.count()).select_from(User)) == 1


@pytest.mark.asyncio
async def test_mode_off_creates_nothing(db_session, monkeypatch):
    monkeypatch.setattr(settings, "BOOTSTRAP_MODE", BootstrapMode.OFF)

    await bootstrap_from_env(db_session)

    assert await db_session.scalar(select(func.count()).select_from(User)) == 0


@pytest.mark.asyncio
async def test_env_mode_without_credentials_fails_loudly(db_session, monkeypatch):
    _use_env_mode(monkeypatch)
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_EMAIL", None)

    with pytest.raises(RuntimeError, match="BOOTSTRAP_ADMIN_EMAIL"):
        await bootstrap_from_env(db_session)

    assert await db_session.scalar(select(func.count()).select_from(User)) == 0


def test_http_mode_without_token_fails_at_startup(monkeypatch):
    _use_http_mode(monkeypatch)
    monkeypatch.setattr(settings, "BOOTSTRAP_TOKEN", None)

    with pytest.raises(RuntimeError, match="BOOTSTRAP_TOKEN"):
        validate_http_bootstrap()


@pytest.mark.asyncio
async def test_missing_admin_role_fails_loudly(db_session, monkeypatch):
    await db_session.execute(delete(DbRole).where(DbRole.name == "ADMIN"))
    await db_session.commit()
    _use_env_mode(monkeypatch)

    with pytest.raises(RuntimeError, match="ADMIN role is missing"):
        await bootstrap_from_env(db_session)

    assert await db_session.scalar(select(func.count()).select_from(User)) == 0


@pytest.mark.asyncio
async def test_env_mode_refuses_existing_non_admin_email(db_session, monkeypatch):
    await create_new_user(
        db_session, UserCreate(email="admin@example.com", password="s3cret!")
    )
    _use_env_mode(monkeypatch)

    with pytest.raises(RuntimeError, match="already exists"):
        await bootstrap_from_env(db_session)

    assert await _admin_count(db_session) == 0


@pytest.mark.asyncio
async def test_http_bootstrap_creates_once_then_conflicts(client, monkeypatch):
    _use_http_mode(monkeypatch)
    payload = {"email": "admin@example.com", "password": "s3cret!"}
    headers = {"X-Bootstrap-Token": "test-bootstrap-token"}

    first = client.post(BOOTSTRAP_URL, json=payload, headers=headers)
    assert first.status_code == 201

    second = client.post(BOOTSTRAP_URL, json=payload, headers=headers)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_http_bootstrap_rejects_bad_or_missing_token(client, monkeypatch):
    _use_http_mode(monkeypatch)
    payload = {"email": "admin@example.com", "password": "s3cret!"}

    missing = client.post(BOOTSTRAP_URL, json=payload)
    assert missing.status_code == 401

    wrong = client.post(
        BOOTSTRAP_URL, json=payload, headers={"X-Bootstrap-Token": "nope"}
    )
    assert wrong.status_code == 401


@pytest.mark.asyncio
async def test_bootstrap_route_is_404_unless_http_mode(client, monkeypatch):
    monkeypatch.setattr(settings, "BOOTSTRAP_MODE", BootstrapMode.OFF)

    response = client.post(
        BOOTSTRAP_URL,
        json={"email": "admin@example.com", "password": "s3cret!"},
        headers={"X-Bootstrap-Token": "anything"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_bootstrapped_admin_can_log_in(client, db_session, monkeypatch):
    _use_env_mode(monkeypatch)
    await bootstrap_from_env(db_session)

    login = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "admin@example.com", "password": "s3cret!"},
    )
    assert login.status_code == 200

    dashboard = client.get(
        f"{settings.API_V1_STR}/admin/dashboard",
        headers={"Authorization": f"Bearer {login.json()['accessToken']}"},
    )
    assert dashboard.status_code == 200
