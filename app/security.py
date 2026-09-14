"""
Minimal JWT access-token handling.

`get_current_user` is the FastAPI equivalent of Nest's Passport JWT
strategy attaching a validated payload to `request.user`: it decodes the
bearer token and trusts the claims inside it (id + role) rather than
re-querying the database on every request. This keeps `RolesGuard` cheap
and DB-free.

NOTE: token *issuance* (login) is intentionally out of scope here — that's
tracked separately in the roadmap. `create_access_token` exists so this
module is self-contained and testable; wire it into a real `/login`
endpoint once that lands.
"""

import uuid
from datetime import UTC, datetime, timedelta

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
    role: Role


def create_access_token(user_id: uuid.UUID, role: Role) -> str:
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "role": role.value,
        "iat": int(now.timestamp()),
        "exp": expire,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> CurrentUser:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
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

        return CurrentUser(id=uuid.UUID(user_id), role=Role(payload["role"]))
    except HTTPException:
        raise
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc