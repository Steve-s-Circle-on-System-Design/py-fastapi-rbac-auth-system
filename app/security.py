"""Minimal JWT access-token handling.

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
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.config import settings
from app.roles import Role

bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser(BaseModel):
    """The decoded JWT payload — the 'passport user' attached to the request."""

    id: uuid.UUID
    role: Role


def create_access_token(user_id: uuid.UUID, role: Role) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"user": str(user_id), "role": role.value, "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ] = None,
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
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        user_id_str = payload.get("user") or payload.get("sub")
        if not user_id_str:
            raise KeyError("user")
        return CurrentUser(id=uuid.UUID(user_id_str), role=Role(payload["role"]))
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
