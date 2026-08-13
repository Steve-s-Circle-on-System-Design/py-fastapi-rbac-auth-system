"""
Minimal JWT access-token handling.

`get_current_user` is the FastAPI equivalent of Nest's Passport JWT
strategy attaching a validated payload to `request.user`: it decodes the
bearer token and trusts the claims inside it (id + role) rather than
re-querying the database on every request. This keeps `RolesGuard` cheap
and DB-free.

NOTE: token *issuance* (login) lives in `app.auth` and signs tokens with
the same secret and algorithm, so `get_current_user` validates those too.
`create_access_token` exists here as a self-contained, testable helper.
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
    payload = {"sub": str(user_id), "role": role.value, "exp": expire}
    return jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


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
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return CurrentUser(id=uuid.UUID(payload["sub"]), role=Role(payload["role"]))
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
