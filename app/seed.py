"""Bootstrap script: seed roles and create the initial admin account.

Usage:
    uv run python -m app.seed --email admin@example.com --password change-me
"""

import argparse
import asyncio

from sqlalchemy import select

from app.auth import ensure_role
from app.database import AsyncSessionLocal
from app.hash import hash_password
from app.models import User, UserRole
from app.roles import Role

DEFAULT_ROLES = (
    (Role.ADMIN.value, "Administrator with full access"),
    (Role.MANAGER.value, "Manager with elevated access"),
    (Role.USER.value, "Regular user"),
)


async def seed(admin_email: str, admin_password: str) -> None:
    async with AsyncSessionLocal() as db:
        for name, description in DEFAULT_ROLES:
            await ensure_role(db, name, description)

        result = await db.execute(select(User).where(User.email == admin_email))
        if result.scalars().first() is not None:
            print(f"Admin {admin_email} already exists, nothing to do.")
            return

        admin = User(email=admin_email, password_hash=hash_password(admin_password))
        db.add(admin)
        await db.flush()
        admin_role = await ensure_role(db, Role.ADMIN.value, DEFAULT_ROLES[0][1])
        db.add(UserRole(user_id=admin.id, role_id=admin_role.id))
        await db.commit()
        print(f"Created admin account: {admin_email}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed roles and an initial admin user."
    )
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--password", default="admin-secret-change-me")
    args = parser.parse_args()
    asyncio.run(seed(args.email, args.password))


if __name__ == "__main__":
    main()
