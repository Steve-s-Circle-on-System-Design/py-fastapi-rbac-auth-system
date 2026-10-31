import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.auth import (
    _hash_refresh_token,
    create_new_user,
    login,
    logout,
    refresh_token,
    revoke_access_token,
    revoke_all_sessions,
)
from app.config import settings
from app.contracts import LoginRequest, UserCreate
from app.models import RefreshToken, RevokeReasonEnum, Role as DbRole, User, UserRole
from app.roles import Role as AppRole
from app.security import create_access_token
from app.tokens import generate_token, validate_token


def make_request():
    return SimpleNamespace(client=None, headers={}, base_url="http://testserver/")


# --- Pure unit tests (no DB) ---


def test_create_access_token_is_three_part_jwt():
    token = create_access_token(uuid.uuid4(), [AppRole.ADMIN])
    assert len(token.split(".")) == 3


def test_create_access_token_claims():
    uid = uuid.uuid4()
    token = create_access_token(uid, [AppRole.ADMIN, AppRole.USER])
    payload = json.loads(
        base64.urlsafe_b64decode(token.split(".")[1] + "==").decode("utf-8")
    )
    assert payload["sub"] == str(uid)
    assert payload["roles"] == ["ADMIN", "USER"]
    assert payload["type"] == "access"
    assert "jti" in payload
    assert payload["exp"] - payload["iat"] == (
        settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


def test_hash_refresh_token_is_deterministic_sha256():
    assert _hash_refresh_token("abc") == _hash_refresh_token("abc")
    assert len(_hash_refresh_token("abc")) == 64


def test_generate_and_validate_token():
    uid = uuid.uuid4()
    token = generate_token(uid)
    payload = validate_token(token)
    assert payload["user"] == str(uid)
    assert payload["type"] == "email_verification"


@pytest.mark.asyncio
async def test_revoke_access_token_ignores_token_without_jti(redis_client):
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "type": "access",
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

    await revoke_access_token(token)

    assert await redis_client.keys("revoked_jti:*") == []


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
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
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

    assert rotated.access_token
    assert rotated.refresh_token != tokens.refresh_token

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


@pytest.mark.asyncio
async def test_create_new_user_assigns_user_role(db_session):
    await _make_user(db_session, email="role@example.com", verified=False)

    role_names = (
        await db_session.scalars(
            select(DbRole.name)
            .join(UserRole, UserRole.role_id == DbRole.id)
            .join(User, User.id == UserRole.user_id)
            .where(User.email == "role@example.com")
        )
    ).all()

    assert set(role_names) == {AppRole.USER.value}


async def _login(db, email="user@example.com"):
    return await login(
        db,
        LoginRequest(email=email, password="s3cret!"),
        make_request(),
    )


async def _token_rows(db, user_id):
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == user_id)
    )
    return result.scalars().all()


@pytest.mark.asyncio
async def test_revoke_all_sessions_marks_every_row_and_clears_redis(
    db_session, redis_client
):
    user = await _make_user(db_session)
    await _login(db_session)
    await _login(db_session)

    await revoke_all_sessions(db_session, user.id)

    rows = await _token_rows(db_session, user.id)
    assert len(rows) == 2
    for row in rows:
        await db_session.refresh(row)
        assert row.is_revoked is True
        assert row.revoke_reason == RevokeReasonEnum.logout_all
        assert row.revoked_at is not None

    assert len(await redis_client.smembers(f"user_sessions:{user.id}")) == 0
    assert await redis_client.get(f"user_revoked_at:{user.id}") is not None


@pytest.mark.asyncio
async def test_revoke_all_sessions_leaves_other_users_untouched(db_session):
    user = await _make_user(db_session, email="a@example.com")
    other = await _make_user(db_session, email="b@example.com")
    await _login(db_session, "a@example.com")
    await _login(db_session, "b@example.com")

    await revoke_all_sessions(db_session, user.id)

    for row in await _token_rows(db_session, other.id):
        await db_session.refresh(row)
        assert row.is_revoked is False
        assert row.revoke_reason is None
        assert row.revoked_at is None


@pytest.mark.asyncio
async def test_revoke_all_sessions_keeps_original_reason_on_revoked_rows(db_session):
    user = await _make_user(db_session)
    first = await _login(db_session)
    await _login(db_session)
    await logout(db_session, first.refresh_token)

    await revoke_all_sessions(db_session, user.id)

    first_row = (
        (
            await db_session.execute(
                select(RefreshToken).where(
                    RefreshToken.token_hash == _hash_refresh_token(first.refresh_token)
                )
            )
        )
        .scalars()
        .one()
    )
    await db_session.refresh(first_row)
    assert first_row.revoke_reason == RevokeReasonEnum.logout

    reasons = {row.revoke_reason for row in await _token_rows(db_session, user.id)}
    assert reasons == {RevokeReasonEnum.logout, RevokeReasonEnum.logout_all}


@pytest.mark.asyncio
async def test_token_reuse_marks_db_rows_with_token_reuse_reason(db_session):
    user = await _make_user(db_session)
    tokens = await _login(db_session)
    await refresh_token(db_session, tokens.refresh_token, make_request())

    with pytest.raises(HTTPException):
        await refresh_token(db_session, tokens.refresh_token, make_request())

    rows = await _token_rows(db_session, user.id)
    assert len(rows) == 2
    for row in rows:
        await db_session.refresh(row)
        assert row.is_revoked is True
    reasons = {row.revoke_reason for row in rows}
    assert reasons == {RevokeReasonEnum.rotated, RevokeReasonEnum.token_reuse}
