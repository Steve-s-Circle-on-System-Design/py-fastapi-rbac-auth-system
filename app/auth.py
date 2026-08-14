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

from app.config import settings
from app.contracts import LoginRequest, TokenPair, UserCreate
from app.hash import hash_password, verify_password
from app.models import (
    RefreshToken,
    RevokeReasonEnum,
    Role as RoleRow,
    User,
    UserRole,
)
from app.roles import Role

ACCESS_TOKEN_LIFETIME = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
REFRESH_TOKEN_LIFETIME = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _create_access_token(user_id: uuid.UUID, role: Role) -> str:
    now = datetime.now(UTC)
    if settings.JWT_ALGORITHM != "HS256":
        raise RuntimeError("Only HS256 access tokens are supported")
    header = _base64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = _base64url_encode(
        json.dumps(
            {
                "sub": str(user_id),
                "role": role.value,
                "type": "access",
                "iat": int(now.timestamp()),
                "exp": int(
                    (
                        now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
                    ).timestamp()
                ),
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
    role: Role,
    token_family: str | None = None,
    parent_token_id: uuid.UUID | None = None,
) -> TokenPair:
    raw_refresh_token = secrets.token_urlsafe(48)
    ip_address, user_agent = _request_metadata(request)
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=_hash_refresh_token(raw_refresh_token),
            token_family=token_family or str(uuid.uuid4()),
            parent_token_id=parent_token_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.now(UTC) + REFRESH_TOKEN_LIFETIME,
        )
    )
    return TokenPair(
        access_token=_create_access_token(user.id, role),
        refresh_token=raw_refresh_token,
        expires_in=int(ACCESS_TOKEN_LIFETIME.total_seconds()),
    )


async def ensure_role(
    db: AsyncSession, name: str, description: str | None = None
) -> RoleRow:
    """Return the role row with `name`, creating it if it does not exist."""
    result = await db.execute(select(RoleRow).where(RoleRow.name == name))
    role = result.scalars().first()
    if role is None:
        role = RoleRow(name=name, description=description)
        db.add(role)
        await db.flush()
    return role


async def _resolve_role(db: AsyncSession, user: User) -> Role:
    """Resolve the user's first assigned role; falls back to `user`."""
    result = await db.execute(
        select(RoleRow.name)
        .join(UserRole, UserRole.role_id == RoleRow.id)
        .where(UserRole.user_id == user.id)
        .limit(1)
    )
    name = result.scalars().first()
    if name is None:
        return Role.USER
    try:
        return Role(name)
    except ValueError:
        return Role.USER


async def create_new_user(db: AsyncSession, user: UserCreate):
    # 1. Check if user exists
    query = select(User).where(User.email == user.email)
    result = await db.execute(query)
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists"
        )

    new_user = User(
        email=user.email,
        password_hash=hash_password(user.password),
    )

    db.add(new_user)
    try:
        await db.flush()
        default_role = await ensure_role(db, Role.USER.value, "Regular user")
        db.add(UserRole(user_id=new_user.id, role_id=default_role.id))
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

    # A lockout window has passed: give the account a fresh set of attempts.
    if user.lockout_until is not None:
        user.lockout_until = None
        user.login_attempts = 0

    # Verify Password
    is_password_correct = verify_password(credentials.password, user.password_hash)

    if not is_password_correct:
        # Increment attempt counter on failure
        user.login_attempts += 1

        # 5th consecutive failure triggers a 15-minute lockout
        if user.login_attempts >= 5:
            user.lockout_until = now + timedelta(
                minutes=settings.ACCOUNT_LOCKOUT_MINUTES
            )

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
    user = await authenticate_user(db, credentials)
    user.last_login = datetime.now(UTC)
    user.last_login_ip = _request_metadata(request)[0]
    role = await _resolve_role(db, user)
    tokens = await _issue_token_pair(db, user, request, role=role)
    await db.commit()
    return tokens


async def refresh_token(
    db: AsyncSession, raw_refresh_token: str, request: Request
) -> TokenPair:
    token_hash = _hash_refresh_token(raw_refresh_token)
    # Locking prevents two simultaneous requests from rotating the same token.
    result = await db.execute(
        select(RefreshToken)
        .where(RefreshToken.token_hash == token_hash)
        .with_for_update()
    )
    token = result.scalars().first()
    if token is None:
        raise _unauthorized()

    now = datetime.now(UTC)
    if token.is_revoked or token.revoked_at is not None:
        # A previously rotated, logged-out, or otherwise revoked token is a
        # reuse signal.  Terminate every still-active refresh session for this user.
        await db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == token.user_id,
                RefreshToken.is_revoked.is_(False),
                RefreshToken.revoked_at.is_(None),
            )
            .values(
                is_revoked=True,
                revoked_at=now,
                revoke_reason=RevokeReasonEnum.token_reuse,
            )
        )
        await db.commit()
        raise _unauthorized()

    if token.expires_at <= now:
        token.revoke(RevokeReasonEnum.expired)
        await db.commit()
        raise _unauthorized()

    if token.created_at <= now - timedelta(days=settings.REFRESH_TOKEN_INACTIVITY_DAYS):
        # The token rotates on every refresh, so the newest token's created_at
        # is a good proxy for the user's last activity.  Idle sessions die
        # without relying on an explicit /logout call.
        token.revoke(RevokeReasonEnum.inactivity)
        await db.commit()
        raise _unauthorized()

    token.revoke(RevokeReasonEnum.rotated)
    user = await db.get(User, token.user_id)
    if user is None:
        await db.rollback()
        raise _unauthorized()
    role = await _resolve_role(db, user)
    tokens = await _issue_token_pair(
        db,
        user,
        request,
        role=role,
        token_family=token.token_family,
        parent_token_id=token.id,
    )
    await db.commit()
    return tokens


async def logout(db: AsyncSession, raw_refresh_token: str) -> None:
    result = await db.execute(
        select(RefreshToken)
        .where(RefreshToken.token_hash == _hash_refresh_token(raw_refresh_token))
        .with_for_update()
    )
    token = result.scalars().first()
    if (
        token is None
        or token.is_revoked
        or token.revoked_at is not None
        or token.expires_at <= datetime.now(UTC)
    ):
        raise _unauthorized()
    token.revoke(RevokeReasonEnum.logout)
    await db.commit()
