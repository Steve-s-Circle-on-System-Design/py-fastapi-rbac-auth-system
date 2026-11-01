"""insert ADMIN and USER roles

Revision ID: c41e7b9a2d58
Revises: 690c4da1ea58
Create Date: 2026-10-31 12:00:00.000000

690c4da1ea58 ("seed roles") was committed with an empty upgrade(), so
databases built through migrations have no roles. This revision inserts
them, skipping any name that already exists.
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c41e7b9a2d58"
down_revision: str | Sequence[str] | None = "690c4da1ea58"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLES = ("ADMIN", "USER")

roles_table = sa.table(
    "roles",
    sa.column("id", sa.UUID()),
    sa.column("name", sa.String()),
)


def upgrade() -> None:
    """Insert the built-in roles that are not already present."""
    bind = op.get_bind()
    existing = set(bind.scalars(sa.select(roles_table.c.name)).all())
    missing = [name for name in ROLES if name not in existing]
    if missing:
        op.bulk_insert(
            roles_table,
            [{"id": uuid.uuid4(), "name": name} for name in missing],
        )


def downgrade() -> None:
    """Remove the built-in roles (user_roles rows cascade)."""
    op.execute(roles_table.delete().where(roles_table.c.name.in_(ROLES)))
