import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select

from app.auth import (
    _create_access_token,
    _hash_refresh_token,
    _resolve_role,
    create_new_user,
    login,
    logout,
    refresh_token,
)
from app.config import settings
from app.contracts import LoginRequest, UserCreate
from app.models import (
    RefreshToken,
    RevokeReasonEnum,
    Role as RoleRow,
    User,
    UserRole,
)
from app.roles import Role
from app.security import get_current_user


def make_request():
    return SimpleNamespace(client=None, headers={})


# --- Pure unit tests (no DB) ---


def test_create_access_token_is_three_part_jwt():
    token = _create_access_token(uuid.uuid4(), Role.USER)
    assert len(token.split(".")) == 3


def test_create_access_token_claims():
    uid = uuid.uuid4()
    token = _create_access_token(uid, Role.USER)
    payload = json.loads(
        base64.urlsafe_b64decode(token.split(".")[1] + "==").decode("utf-8")
    )
    assert payload["sub"] == str(uid)
    assert payload["role"] == Role.USER.value
    assert payload["type"] == "access"
    assert payload["exp"] - payload["iat"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


def test_create_access_token_algorithm_is_hs256():
    token = _create_access_token(uuid.uuid4(), Role.USER)
    header = json.loads(
        base64.urlsafe_b64decode(token.split(".")[0] + "==").decode("utf-8")
    )
    assert header["alg"] == "HS256"


def test_create_access_token_rejects_unsupported_algorithm(monkeypatch):
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "RS256")
    with pytest.raises(RuntimeError):
        _create_access_token(uuid.uuid4(), Role.USER)


def test_hash_refresh_token_is_deterministic_sha256():
    assert _hash_refresh_token("abc") == _hash_refresh_token("abc")
    assert len(_hash_refresh_token("abc")) == 64


@pytest.mark.asyncio
async def test_access_token_verifies_valid_token():
    uid = uuid.uuid4()
    token = _create_access_token(uid, Role.ADMIN)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    current = await get_current_user(credentials)
    assert current.id == uid
    assert current.role == Role.ADMIN


@pytest.mark.asyncio
async def test_expired_access_token_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", -1)
    token = _create_access_token(uuid.uuid4(), Role.USER)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc:
        await get_current_user(credentials)
    assert exc.value.status_code == 401


# --- DB-backed auth flows ---


async def _make_user(db, email="user@example.com", password="s3cret!"):
    return await create_new_user(db, UserCreate(email=email, password=password))


async def _fetch_token(db, raw_refresh_token) -> RefreshToken:
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == _hash_refresh_token(raw_refresh_token)
        )
    )
    return result.scalars().one()


@pytest.mark.asyncio
async def test_create_new_user_hashes_password(db_session):
    user = await _make_user(db_session)
    assert user.id is not None
    assert user.password_hash.startswith("$2")
    assert user.password_hash != "s3cret!"


@pytest.mark.asyncio
async def test_create_new_user_assigns_default_role(db_session):
    user = await _make_user(db_session)
    result = await db_session.execute(
        select(RoleRow.name)
        .join(UserRole, UserRole.role_id == RoleRow.id)
        .where(UserRole.user_id == user.id)
    )
    assert result.scalars().all() == [Role.USER.value]


@pytest.mark.asyncio
async def test_create_new_user_rejects_duplicate_email(db_session):
    await _make_user(db_session, email="dup@example.com")
    with pytest.raises(HTTPException) as exc:
        await _make_user(db_session, email="dup@example.com")
    assert exc.value.status_code == 400
    assert "already exists" in exc.value.detail


@pytest.mark.asyncio
async def test_login_returns_token_pair(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    assert tokens.access_token
    assert tokens.refresh_token


@pytest.mark.asyncio
async def test_login_issued_token_carries_role_claim(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    payload = jwt.decode(
        tokens.access_token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
    assert payload["role"] == Role.USER.value
    assert payload["exp"] - payload["iat"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


@pytest.mark.asyncio
async def test_login_rejects_wrong_password(db_session):
    await _make_user(db_session)
    with pytest.raises(HTTPException) as exc:
        await login(
            db_session,
            LoginRequest(email="user@example.com", password="wrong"),
            make_request(),
        )
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_login_rejects_unknown_email(db_session):
    with pytest.raises(HTTPException) as exc:
        await login(
            db_session,
            LoginRequest(email="nobody@example.com", password="s3cret!"),
            make_request(),
        )
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_login_token_has_no_parent_and_new_family(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    row = await _fetch_token(db_session, tokens.refresh_token)
    assert row.parent_token_id is None
    assert row.token_family


@pytest.mark.asyncio
async def test_refresh_token_ttl_matches_settings(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    row = await _fetch_token(db_session, tokens.refresh_token)
    expected = datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    assert abs(row.expires_at - expected) < timedelta(seconds=5)


@pytest.mark.asyncio
async def test_refresh_rotates_token(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    old_token = tokens.refresh_token
    new_pair = await refresh_token(db_session, old_token, make_request())
    assert new_pair.refresh_token != old_token

    old_row = await _fetch_token(db_session, old_token)
    assert old_row.is_revoked is True
    assert old_row.revoke_reason == RevokeReasonEnum.rotated


@pytest.mark.asyncio
async def test_refresh_child_links_parent_token(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    new_pair = await refresh_token(db_session, tokens.refresh_token, make_request())

    old_row = await _fetch_token(db_session, tokens.refresh_token)
    new_row = await _fetch_token(db_session, new_pair.refresh_token)
    assert new_row.parent_token_id == old_row.id
    assert new_row.token_family == old_row.token_family


@pytest.mark.asyncio
async def test_refresh_token_reuse_is_detected(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    await refresh_token(db_session, tokens.refresh_token, make_request())

    with pytest.raises(HTTPException) as exc:
        await refresh_token(db_session, tokens.refresh_token, make_request())
    assert exc.value.status_code == 401

    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.is_revoked.is_(True))
    )
    assert len(result.scalars().all()) == 2


@pytest.mark.asyncio
async def test_refresh_expired_token_rejected(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    row = await _fetch_token(db_session, tokens.refresh_token)
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc:
        await refresh_token(db_session, tokens.refresh_token, make_request())
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_refresh_after_inactivity_window_rejected(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    row = await _fetch_token(db_session, tokens.refresh_token)
    row.created_at = datetime.now(UTC) - timedelta(
        days=settings.REFRESH_TOKEN_INACTIVITY_DAYS + 1
    )
    await db_session.commit()

    with pytest.raises(HTTPException) as exc:
        await refresh_token(db_session, tokens.refresh_token, make_request())
    assert exc.value.status_code == 401

    await db_session.refresh(row)
    assert row.is_revoked is True
    assert row.revoke_reason == RevokeReasonEnum.inactivity


@pytest.mark.asyncio
async def test_logout_revokes_token(db_session):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    await logout(db_session, tokens.refresh_token)

    row = await _fetch_token(db_session, tokens.refresh_token)
    assert row.is_revoked is True
    assert row.revoke_reason == RevokeReasonEnum.logout


@pytest.mark.asyncio
async def test_account_locks_after_five_failed_attempts(db_session):
    user = await _make_user(db_session)
    for _ in range(5):
        with pytest.raises(HTTPException) as exc:
            await login(
                db_session,
                LoginRequest(email="user@example.com", password="wrong"),
                make_request(),
            )
        assert exc.value.status_code == 401

    # 5th failure arms a 15-minute lockout window.
    await db_session.refresh(user)
    expected = datetime.now(UTC) + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
    assert abs(user.lockout_until - expected) < timedelta(seconds=5)

    # Even the correct password is rejected while locked out.
    with pytest.raises(HTTPException) as exc:
        await login(
            db_session,
            LoginRequest(email="user@example.com", password="s3cret!"),
            make_request(),
        )
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_lockout_clears_after_window_passes(db_session):
    user = await _make_user(db_session)
    for _ in range(5):
        with pytest.raises(HTTPException):
            await login(
                db_session,
                LoginRequest(email="user@example.com", password="wrong"),
                make_request(),
            )

    # Simulate the 15-minute window elapsing.
    user.lockout_until = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    # A fresh failure after the window is a normal 401, and the counter restarts.
    with pytest.raises(HTTPException) as exc:
        await login(
            db_session,
            LoginRequest(email="user@example.com", password="wrong"),
            make_request(),
        )
    assert exc.value.status_code == 401
    await db_session.refresh(user)
    assert user.lockout_until is None
    assert user.login_attempts == 1


@pytest.mark.asyncio
async def test_successful_login_resets_lockout_counter(db_session):
    await _make_user(db_session)
    for _ in range(4):
        with pytest.raises(HTTPException):
            await login(
                db_session,
                LoginRequest(email="user@example.com", password="wrong"),
                make_request(),
            )
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    assert tokens.access_token


@pytest.mark.asyncio
async def test_resolve_role_defaults_to_user_when_no_roles(db_session):
    user = User(email="norole@example.com", password_hash="unused-hash")
    db_session.add(user)
    await db_session.commit()

    assert await _resolve_role(db_session, user) == Role.USER


@pytest.mark.asyncio
async def test_resolve_role_defaults_to_user_for_unknown_role_name(db_session):
    user = User(email="weird@example.com", password_hash="unused-hash")
    db_session.add(user)
    await db_session.flush()
    weird = RoleRow(name="superhero", description="not part of the app enum")
    db_session.add(weird)
    await db_session.flush()
    db_session.add(UserRole(user_id=user.id, role_id=weird.id))
    await db_session.commit()

    assert await _resolve_role(db_session, user) == Role.USER
