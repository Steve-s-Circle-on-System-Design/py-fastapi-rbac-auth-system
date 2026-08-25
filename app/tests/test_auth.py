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
from app.config import settings
from app.contracts import LoginRequest, UserCreate
from app.models import RefreshToken, RevokeReasonEnum


def make_request():
    return SimpleNamespace(client=None, headers={})


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
    assert payload["sub"] == str(uid)
    assert payload["type"] == "access"
    assert payload["exp"] - payload["iat"] == 15 * 60


def test_create_access_token_algorithm_is_hs256():
    token = _create_access_token(uuid.uuid4())
    header = json.loads(
        base64.urlsafe_b64decode(token.split(".")[0] + "==").decode("utf-8")
    )
    assert header["alg"] == "HS256"


def test_create_access_token_rejects_unsupported_algorithm(monkeypatch):
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "RS256")
    with pytest.raises(RuntimeError):
        _create_access_token(uuid.uuid4())


def test_hash_refresh_token_is_deterministic_sha256():
    assert _hash_refresh_token("abc") == _hash_refresh_token("abc")
    assert len(_hash_refresh_token("abc")) == 64


# --- DB-backed auth flows ---


async def _make_user(db, email="user@example.com", password="s3cret!"):
    return await create_new_user(db, UserCreate(email=email, password=password))


@pytest.mark.asyncio
async def test_create_new_user_hashes_password(db_session):
    user = await _make_user(db_session)
    assert user.id is not None
    assert user.password_hash.startswith("$2")
    assert user.password_hash != "s3cret!"


@pytest.mark.asyncio
async def test_create_new_user_rejects_duplicate_email(db_session):
    await _make_user(db_session, email="dup@example.com")
    with pytest.raises(HTTPException) as exc:
        await _make_user(db_session, email="dup@example.com")
    assert exc.value.status_code == 400


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
async def test_refresh_expired_token_rejected(db_session, redis_client):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    token_hash = _hash_refresh_token(tokens.refresh_token)

    # Evict token from Redis as if TTL expired
    await redis_client.delete(f"refresh_token:{token_hash}")

    with pytest.raises(HTTPException) as exc:
        await refresh_token(db_session, tokens.refresh_token, make_request())
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_token(db_session, redis_client):
    await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    token_hash = _hash_refresh_token(tokens.refresh_token)

    # Verify session is stored in Redis before logout
    raw_redis_session = await redis_client.get(f"refresh_token:{token_hash}")
    assert raw_redis_session is not None

    await logout(db_session, tokens.refresh_token)

    # Verify session is deleted from Redis after logout
    raw_redis_session_after = await redis_client.get(f"refresh_token:{token_hash}")
    assert raw_redis_session_after is None

    result = await db_session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash
        )
    )
    row = result.scalars().one()
    assert row.is_revoked is True
    assert row.revoke_reason == RevokeReasonEnum.logout


@pytest.mark.asyncio
async def test_redis_user_session_revocation_on_token_reuse(db_session, redis_client):
    user = await _make_user(db_session)
    tokens = await login(
        db_session,
        LoginRequest(email="user@example.com", password="s3cret!"),
        make_request(),
    )
    # First rotation succeeds
    rotated = await refresh_token(db_session, tokens.refresh_token, make_request())

    # Replaying old token triggers token reuse protection via Redis
    with pytest.raises(HTTPException) as exc:
        await refresh_token(db_session, tokens.refresh_token, make_request())
    assert exc.value.status_code == 401

    # User active sessions in Redis should be completely cleared
    active_sessions = await redis_client.smembers(f"user_sessions:{user.id}")
    assert len(active_sessions) == 0

    # User revocation timestamp should be recorded in Redis
    revoked_at = await redis_client.get(f"user_revoked_at:{user.id}")
    assert revoked_at is not None

