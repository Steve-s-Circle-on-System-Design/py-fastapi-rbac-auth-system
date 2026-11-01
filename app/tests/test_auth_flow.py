"""End-to-end auth flow: tokens from a real login must satisfy RolesGuard."""

import time
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, insert, select

from app.auth import create_new_user
from app.config import settings
from app.contracts import UserCreate
from app.models import Role as DbRole, UserRole
from app.redis_store import token_store
from app.roles import Role as AppRole

PASSWORD = "s3cret!"


async def _create_verified_user(db, email: str, role: AppRole):
    """Create a user directly with exactly one role — the bootstrap stand-in."""
    user = await create_new_user(db, UserCreate(email=email, password=PASSWORD))
    user.is_verified = True
    user.email_verified_at = datetime.now(UTC)

    role_row = await db.scalar(select(DbRole).where(DbRole.name == role.value))
    assert role_row is not None

    # create_new_user assigns USER; replace it so the user has exactly `role`.
    await db.execute(delete(UserRole).where(UserRole.user_id == user.id))
    await db.execute(insert(UserRole).values(user_id=user.id, role_id=role_row.id))
    await db.commit()
    return user


def _login_response(client, email: str) -> dict:
    response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _login(client, email: str) -> dict[str, str]:
    access = _login_response(client, email)["accessToken"]
    return {"Authorization": f"Bearer {access}"}


@pytest.mark.asyncio
async def test_admin_login_token_reaches_guarded_routes(client, db_session):
    await _create_verified_user(db_session, "admin@example.com", AppRole.ADMIN)
    headers = _login(client, "admin@example.com")

    dashboard = client.get(f"{settings.API_V1_STR}/admin/dashboard", headers=headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["message"] == "Welcome to the admin dashboard"

    created = client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "member@example.com", "password": PASSWORD},
        headers=headers,
    )
    assert created.status_code == 201
    assert created.json()["roles"] == [AppRole.USER.value]


@pytest.mark.asyncio
async def test_missing_and_revoked_tokens_are_rejected(client, db_session):
    user = await _create_verified_user(db_session, "admin@example.com", AppRole.ADMIN)

    no_token = client.get(f"{settings.API_V1_STR}/admin/dashboard")
    assert no_token.status_code == 401

    headers = _login(client, "admin@example.com")
    assert (
        client.get(
            f"{settings.API_V1_STR}/admin/dashboard", headers=headers
        ).status_code
        == 200
    )

    await token_store.revoke_user_sessions(str(user.id))

    revoked = client.get(f"{settings.API_V1_STR}/admin/dashboard", headers=headers)
    assert revoked.status_code == 401


@pytest.mark.asyncio
async def test_member_login_token_is_forbidden(client, db_session):
    await _create_verified_user(db_session, "member@example.com", AppRole.USER)
    headers = _login(client, "member@example.com")

    dashboard = client.get(f"{settings.API_V1_STR}/admin/dashboard", headers=headers)
    assert dashboard.status_code == 403

    created = client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "other@example.com", "password": PASSWORD},
        headers=headers,
    )
    assert created.status_code == 403


@pytest.mark.asyncio
async def test_logout_revokes_the_access_token(client, db_session):
    await _create_verified_user(db_session, "admin@example.com", AppRole.ADMIN)
    tokens = _login_response(client, "admin@example.com")
    headers = {"Authorization": f"Bearer {tokens['accessToken']}"}
    dashboard = f"{settings.API_V1_STR}/admin/dashboard"

    assert client.get(dashboard, headers=headers).status_code == 200

    out = client.post(
        f"{settings.API_V1_STR}/auth/logout",
        json={"refreshToken": tokens["refreshToken"]},
        headers=headers,
    )
    assert out.status_code == 204

    assert client.get(dashboard, headers=headers).status_code == 401


@pytest.mark.asyncio
async def test_logout_without_access_token_still_revokes_refresh(client, db_session):
    await _create_verified_user(db_session, "admin@example.com", AppRole.ADMIN)
    tokens = _login_response(client, "admin@example.com")

    out = client.post(
        f"{settings.API_V1_STR}/auth/logout",
        json={"refreshToken": tokens["refreshToken"]},
    )
    assert out.status_code == 204

    replay = client.post(
        f"{settings.API_V1_STR}/auth/refresh",
        json={"refreshToken": tokens["refreshToken"]},
    )
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_logout_all_ends_every_session(client, db_session):
    await _create_verified_user(db_session, "admin@example.com", AppRole.ADMIN)
    first = _login_response(client, "admin@example.com")
    second = _login_response(client, "admin@example.com")
    dashboard = f"{settings.API_V1_STR}/admin/dashboard"
    first_headers = {"Authorization": f"Bearer {first['accessToken']}"}
    second_headers = {"Authorization": f"Bearer {second['accessToken']}"}

    assert client.get(dashboard, headers=first_headers).status_code == 200
    assert client.get(dashboard, headers=second_headers).status_code == 200

    out = client.post(f"{settings.API_V1_STR}/auth/logout-all", headers=first_headers)
    assert out.status_code == 204

    # Both access tokens are dead, not only the one used for the call.
    assert client.get(dashboard, headers=first_headers).status_code == 401
    assert client.get(dashboard, headers=second_headers).status_code == 401

    # Both refresh tokens are dead too.
    for tokens in (first, second):
        replay = client.post(
            f"{settings.API_V1_STR}/auth/refresh",
            json={"refreshToken": tokens["refreshToken"]},
        )
        assert replay.status_code == 401


@pytest.mark.asyncio
async def test_logout_all_requires_authentication(client):
    out = client.post(f"{settings.API_V1_STR}/auth/logout-all")
    assert out.status_code == 401


@pytest.mark.asyncio
async def test_login_after_logout_all_works(client, db_session):
    await _create_verified_user(db_session, "admin@example.com", AppRole.ADMIN)
    headers = _login(client, "admin@example.com")
    assert (
        client.post(
            f"{settings.API_V1_STR}/auth/logout-all", headers=headers
        ).status_code
        == 204
    )

    # Token times are whole seconds, so a login in the same second as the
    # revocation would be rejected. Wait it out.
    time.sleep(1.1)

    fresh = _login(client, "admin@example.com")
    dashboard = client.get(f"{settings.API_V1_STR}/admin/dashboard", headers=fresh)
    assert dashboard.status_code == 200
