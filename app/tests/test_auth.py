import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.auth import (
    _create_access_token,
    _hash_refresh_token,
    create_new_user,
    login,
    logout,
    refresh_token,
)
from app.contracts import LoginRequest, UserCreate
from app.models import RefreshToken, RevokeReasonEnum
from app.tokens import generate_token, validate_token


def make_request():
    return SimpleNamespace(client=None, headers={}, base_url="http://testserver/")


# --- Pure unit tests (no DB) ---


def test_create_access_token_is_three_part_jwt():
    token = _create_access_token(uuid.uuid4())
    assert len(token.split(".")) == 3


def test_create_access_token_claims():
    uid = uuid.uuid4()
    token = _create_access_token(uid)
    payload = json.loads(
        base64.urlsafe_b64decode(token.split(".")[1] + "==").decode("utf-8")
    )
    assert payload["user"] == str(uid)
    assert payload["type"] == "access"
    assert "jti" in payload
    assert payload["exp"] - payload["iat"] == 15 * 60


def test_hash_refresh_token_is_deterministic_sha256():
    assert _hash_refresh_token("abc") == _hash_refresh_token("abc")
    assert len(_hash_refresh_token("abc")) == 64


def test_generate_and_validate_token():
    uid = uuid.uuid4()
    token = generate_token(uid)
    payload = validate_token(token)
    assert payload["user"] == str(uid)
    assert payload["type"] == "email_verification"


# --- DB-backed auth flows ---


async def _make_user(db, email="user@example.com", password="s3cret!", verified=True):
    user = await create_new_user(db, UserCreate(email=email, password=password))
    if verified:
        user.is_verified = True
        user.email_verified_at = datetime.now(UTC)
        await db.commit()
    return user


@pytest.mark.asyncio
async def test_create_new_user_hashes_password(db_session):
    user = await _make_user(db_session, verified=False)
    assert user.id is not None
    assert user.password_hash.startswith("$2")
    assert user.password_hash != "s3cret!"
    assert user.is_verified is False


@pytest.mark.asyncio
async def test_create_new_user_rejects_duplicate_email(db_session):
    await _make_user(db_session, email="dup@example.com")
    with pytest.raises(HTTPException) as exc:
        await _make_user(db_session, email="dup@example.com")
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_login_returns_token_pair(db_session):
    await _make_user(db_session, verified=True)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    assert tokens.access_token
    assert tokens.refresh_token


@pytest.mark.asyncio
async def test_login_rejects_wrong_password(db_session):
    await _make_user(db_session, verified=True)
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
async def test_brute_force_lockout_five_failed_attempts(db_session):
    user = await _make_user(
        db_session, email="lockout@example.com", password="s3cret!", verified=True
    )
    req = make_request()
    wrong_creds = LoginRequest(email="lockout@example.com", password="wrong")

    # 4 wrong attempts
    for _ in range(4):
        with pytest.raises(HTTPException) as exc:
            await login(db_session, wrong_creds, req)
        assert exc.value.status_code == 401

    await db_session.refresh(user)
    assert user.failed_login_attempts == 4
    assert user.lockout_until is None

    # 5th wrong attempt triggers 15-minute lockout
    with pytest.raises(HTTPException) as exc:
        await login(db_session, wrong_creds, req)
    assert exc.value.status_code == 401

    await db_session.refresh(user)
    assert user.failed_login_attempts == 5
    assert user.lockout_until is not None

    # 6th attempt with CORRECT password during lockout is denied immediately (403)
    correct_creds = LoginRequest(email="lockout@example.com", password="s3cret!")
    with pytest.raises(HTTPException) as exc:
        await login(db_session, correct_creds, req)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_lockout_expires_dynamically(db_session):
    user = await _make_user(
        db_session, email="dynamic@example.com", password="s3cret!", verified=True
    )
    user.lockout_until = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    tokens = await login(
        db_session,
        LoginRequest(email="dynamic@example.com", password="s3cret!"),
        make_request(),
    )
    assert tokens.access_token
    await db_session.refresh(user)
    assert user.failed_login_attempts == 0
    assert user.lockout_until is None


@pytest.mark.asyncio
async def test_unverified_login_rate_limiting(db_session):
    # Registration auto-sends first verification email
    await _make_user(
        db_session, email="unverified@example.com", password="s3cret!", verified=False
    )
    req = make_request()
    creds = LoginRequest(email="unverified@example.com", password="s3cret!")

    # Attempt login within 5 minutes -> 429 Too Many Requests
    with pytest.raises(HTTPException) as exc:
        await login(db_session, creds, req)
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_refresh_rotates_token(db_session):
    await _make_user(db_session, verified=True)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    old_token = tokens.refresh_token
    new_pair = await refresh_token(db_session, old_token, make_request())
    assert new_pair.refresh_token != old_token

    result = await db_session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == _hash_refresh_token(old_token)
        )
    )
    old_row = result.scalars().one()
    assert old_row.is_revoked is True
    assert old_row.revoke_reason == RevokeReasonEnum.rotated


@pytest.mark.asyncio
async def test_refresh_token_reuse_is_detected(db_session):
    await _make_user(db_session, verified=True)
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
async def test_logout_revokes_token(db_session):
    await _make_user(db_session, verified=True)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    await logout(db_session, tokens.refresh_token)

    result = await db_session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == _hash_refresh_token(tokens.refresh_token)
        )
    )
    row = result.scalars().one()
    assert row.is_revoked is True
    assert row.revoke_reason == RevokeReasonEnum.logout
