import base64
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, UTC

from app.config import settings
from app.contracts import LoginRequest, TokenPair, UserCreate
from app.hash import hash_password, verify_password
from app.models import RefreshToken, RevokeReasonEnum, User
from app.redis_store import token_store

ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
REFRESH_TOKEN_LIFETIME = timedelta(days=7)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _create_access_token(user_id: uuid.UUID) -> str:
    now = datetime.now(UTC)
    if settings.JWT_ALGORITHM != "HS256":
        raise RuntimeError("Only HS256 access tokens are supported")
    header = _base64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = _base64url_encode(
        json.dumps(
            {
                "sub": str(user_id),
                "type": "access",
                "iat": int(now.timestamp()),
                "exp": int((now + ACCESS_TOKEN_LIFETIME).timestamp()),
                "jti": str(uuid.uuid4()),
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(
        settings.JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    return f"{header}.{payload}.{_base64url_encode(signature)}"


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _request_metadata(request: Request) -> tuple[str | None, str | None]:
    client_ip = request.client.host if request.client else None
    return client_ip, request.headers.get("user-agent")


async def _issue_token_pair(
    db: AsyncSession,
    user: User,
    request: Request,
    *,
    token_family: str | None = None,
    parent_token_id: uuid.UUID | None = None,
) -> TokenPair:
    raw_refresh_token = secrets.token_urlsafe(48)
    token_hash = _hash_refresh_token(raw_refresh_token)
    ip_address, user_agent = _request_metadata(request)
    tf = token_family or str(uuid.uuid4())

    db_refresh_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        token_family=tf,
        parent_token_id=parent_token_id,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=datetime.now(UTC) + REFRESH_TOKEN_LIFETIME,
    )
    db.add(db_refresh_token)

    # Redis Token Store session creation
    session_data = {
        "user_id": str(user.id),
        "token_family": tf,
        "parent_token_id": str(parent_token_id) if parent_token_id else None,
        "ip_address": ip_address,
        "user_agent": user_agent,
    }
    await token_store.store_refresh_token(
        token_hash=token_hash,
        session_data=session_data,
        ttl_seconds=int(REFRESH_TOKEN_LIFETIME.total_seconds()),
    )

    return TokenPair(
        access_token=_create_access_token(user.id), refresh_token=raw_refresh_token
    )


async def create_new_user(db: AsyncSession, user: UserCreate):
    # 1. Check if user exists
    query = select(User).where(User.email == user.email)
    result = await db.execute(query)
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    new_user = User(
        email=user.email,
        password_hash=hash_password(user.password),
    )

    db.add(new_user)
    try:
        await db.commit()
        await db.refresh(new_user)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Database error") from e

    return new_user


# user authentication function with lockout mechanism
async def authenticate_user(db: AsyncSession, credentials: LoginRequest) -> User:
    # 1. Check if user exists
    query = select(User).where(User.email == credentials.email)
    result = await db.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # ACCEPTANCE CRITERIA: Reject instantly if lockout is active
    now = datetime.now(UTC)
    if user.lockout_until and user.lockout_until > now:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account locked due to multiple failed attempts. Try again later.",
        )

    # Verify Password
    is_password_correct = verify_password(credentials.password, user.password_hash)

    if not is_password_correct:
        # Increment attempt counter on failure
        user.login_attempts += 1

        # 5th failure = 15-minute lockout
        if user.login_attempts >= 5:
            user.lockout_until = now + timedelta(minutes=5)

        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Reset counters
    user.login_attempts = 0
    user.lockout_until = None
    await db.commit()

    return user


async def login(
    db: AsyncSession, credentials: LoginRequest, request: Request
) -> TokenPair:
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalars().first()
    if (
        not user
        or not user.password_hash
        or not verify_password(credentials.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user.last_login = datetime.now(UTC)
    user.last_login_ip = _request_metadata(request)[0]
    tokens = await _issue_token_pair(db, user, request)
    await db.commit()
    return tokens


async def refresh_token(
    db: AsyncSession, raw_refresh_token: str, request: Request
) -> TokenPair:
    token_hash = _hash_refresh_token(raw_refresh_token)

    # 1. Reuse detection via Redis
    if await token_store.is_token_used(token_hash):
        # A rotated token was presented again! Invalidate all Redis sessions for user.
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        db_token = result.scalars().first()
        if db_token:
            await token_store.revoke_user_sessions(str(db_token.user_id))
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.user_id == db_token.user_id,
                    RefreshToken.is_revoked.is_(False),
                    RefreshToken.revoked_at.is_(None),
                )
                .values(
                    is_revoked=True,
                    revoked_at=datetime.now(UTC),
                    revoke_reason=RevokeReasonEnum.token_reuse,
                )
            )
            await db.commit()
        raise _unauthorized()

    # 2. Retrieve session from Redis
    session_data = await token_store.get_refresh_token(token_hash)
    if session_data is None:
        # Check DB to see if this was a previously revoked token (reuse signal)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        db_token = result.scalars().first()
        if db_token and (db_token.is_revoked or db_token.revoked_at is not None):
            await token_store.revoke_user_sessions(str(db_token.user_id))
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.user_id == db_token.user_id,
                    RefreshToken.is_revoked.is_(False),
                    RefreshToken.revoked_at.is_(None),
                )
                .values(
                    is_revoked=True,
                    revoked_at=datetime.now(UTC),
                    revoke_reason=RevokeReasonEnum.token_reuse,
                )
            )
            await db.commit()
        raise _unauthorized()

    user_id = uuid.UUID(session_data["user_id"])
    token_family = session_data.get("token_family")

    # Mark token used in Redis for rotation tracking & reuse protection
    await token_store.mark_token_used(
        token_hash, int(REFRESH_TOKEN_LIFETIME.total_seconds())
    )
    # Revoke old refresh token session from Redis
    await token_store.revoke_refresh_token(token_hash)

    # Sync PostgreSQL DB model for audit logging
    result = await db.execute(
        select(RefreshToken)
        .where(RefreshToken.token_hash == token_hash)
        .with_for_update()
    )
    db_token = result.scalars().first()
    parent_token_id = None
    if db_token:
        db_token.revoke(RevokeReasonEnum.rotated)
        parent_token_id = db_token.id

    user = await db.get(User, user_id)
    if user is None:
        await db.rollback()
        raise _unauthorized()

    tokens = await _issue_token_pair(
        db,
        user,
        request,
        token_family=token_family,
        parent_token_id=parent_token_id,
    )
    await db.commit()
    return tokens


async def logout(db: AsyncSession, raw_refresh_token: str) -> None:
    token_hash = _hash_refresh_token(raw_refresh_token)

    # Check session in Redis
    session_data = await token_store.get_refresh_token(token_hash)

    result = await db.execute(
        select(RefreshToken)
        .where(RefreshToken.token_hash == token_hash)
        .with_for_update()
    )
    db_token = result.scalars().first()

    if session_data is None and (
        db_token is None
        or db_token.is_revoked
        or db_token.revoked_at is not None
        or db_token.expires_at <= datetime.now(UTC)
    ):
        raise _unauthorized()

    # Revoke token session in Redis
    await token_store.revoke_refresh_token(token_hash)

    if db_token and not db_token.is_revoked:
        db_token.revoke(RevokeReasonEnum.logout)
        await db.commit()

