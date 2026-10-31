"""Create the first admin on a fresh deployment.

A new database has no way in: `POST /users` is admin-guarded and there is no
signup endpoint, so nobody can create the first account. `ensure_admin` runs
at startup, creates exactly one verified admin, and then does nothing on every
later start.
"""

import logging
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import BootstrapMode, settings
from app.hash import hash_password
from app.models import Role as DbRole, User, UserRole
from app.roles import Role

logger = logging.getLogger(__name__)

# Arbitrary constant. Two workers starting together take this lock, so only one
# of them can pass the "is there an admin?" check and insert.
BOOTSTRAP_LOCK_KEY = 72_401_133


async def ensure_admin(db: AsyncSession, email: str, password: str) -> bool:
    """Create the first ADMIN once. Returns True if one was created.

    Expects a session with no pending work. The advisory lock is released by
    the commit at the end of either branch.
    """
    if not email or not password:
        raise RuntimeError("bootstrap needs both an email and a password")
    if "@" not in email:
        raise RuntimeError(f"bootstrap email is not a valid address: {email}")

    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"), {"key": BOOTSTRAP_LOCK_KEY}
    )

    admin_role = await db.scalar(select(DbRole).where(DbRole.name == Role.ADMIN.value))
    if admin_role is None:
        raise RuntimeError(
            "ADMIN role is missing from the roles table; run `alembic upgrade head`"
        )

    admin_exists = await db.scalar(
        select(User.id)
        .join(UserRole, UserRole.user_id == User.id)
        .where(UserRole.role_id == admin_role.id)
        .limit(1)
    )
    if admin_exists is not None:
        await db.commit()
        return False

    email_taken = await db.scalar(select(User.id).where(User.email == email))
    if email_taken is not None:
        raise RuntimeError(
            f"cannot bootstrap: {email} already exists without the ADMIN role"
        )

    db.add(
        User(
            email=email,
            password_hash=hash_password(password),
            is_verified=True,
            email_verified_at=datetime.now(UTC),
            roles=[admin_role],
        )
    )
    await db.commit()
    logger.info("bootstrap: created ADMIN account %s", email)
    return True


def validate_http_bootstrap() -> None:
    """Fail at startup when http mode has no token."""
    if settings.BOOTSTRAP_MODE is BootstrapMode.HTTP and not settings.BOOTSTRAP_TOKEN:
        raise RuntimeError("BOOTSTRAP_MODE=http but BOOTSTRAP_TOKEN is empty")


def _env_credentials() -> tuple[str, str] | None:
    """Return the env credentials, or None when env mode is not selected."""
    if settings.BOOTSTRAP_MODE is not BootstrapMode.ENV:
        return None

    email = settings.BOOTSTRAP_ADMIN_EMAIL
    password = settings.BOOTSTRAP_ADMIN_PASSWORD
    if not email or not password:
        raise RuntimeError(
            "BOOTSTRAP_MODE=env but BOOTSTRAP_ADMIN_EMAIL or "
            "BOOTSTRAP_ADMIN_PASSWORD is empty"
        )
    return email, password


async def bootstrap_from_env(db: AsyncSession) -> None:
    """Bootstrap from settings when `BOOTSTRAP_MODE` is `env`."""
    credentials = _env_credentials()
    if credentials is None:
        return

    await ensure_admin(db, *credentials)
