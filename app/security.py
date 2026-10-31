"""
Minimal JWT access-token handling.

`get_current_user` is the FastAPI equivalent of Nest's Passport JWT
strategy attaching a validated payload to `request.user`: it decodes the
bearer token and trusts the claims inside it (id + roles) rather than
re-querying the database on every request. This keeps `RolesGuard` cheap
and DB-free.

NOTE: create_access_token is the single issuer for access tokens; auth calls it
on login and refresh so the claims can never drift from what this module
verifies.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.config import settings
from app.redis_store import token_store
from app.roles import Role

bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser(BaseModel):
    """The decoded JWT payload — the 'passport user' attached to the request."""

    id: uuid.UUID
    roles: set[Role]


def create_access_token(user_id: uuid.UUID, roles: list[Role]) -> str:
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "roles": [role.value for role in roles],
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": expire,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def decode_access_token(token: str) -> dict:
    """Decode an access token, raising `jwt.PyJWTError` if it is not valid."""
    return jwt.decode(
        token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
    )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> CurrentUser:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)

        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = str(payload["sub"])
        iat = int(payload.get("iat", 0))
        jti = payload.get("jti")

        # Session invalidation check in Redis
        is_revoked = await token_store.is_access_token_revoked(
            user_id=user_id, iat=iat, jti=jti
        )
        if is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked or session invalidated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        raw_roles = payload.get("roles") or []
        return CurrentUser(
            id=uuid.UUID(user_id),
            roles={Role(name) for name in raw_roles},
        )
    except HTTPException:
        raise
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
