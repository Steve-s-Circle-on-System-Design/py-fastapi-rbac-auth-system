"""lockout and verification fields

Revision ID: 993555dcf39d
Revises: ba468afbb3c6
Create Date: 2026-08-03 03:29:37.862356

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "993555dcf39d"
down_revision: str | Sequence[str] | None = "ba468afbb3c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_REASONS = (
    "logout",
    "logout_all",
    "password_change",
    "token_reuse",
    "account_suspended",
    "session_hijack_suspected",
    "rotated",
    "expired",
)

_NEW_REASONS = (*_OLD_REASONS, "inactivity")

_ENUM_CONSTRAINT = "revokereasonenum"


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column("users", "locked_until", new_column_name="lockout_until")
    op.add_column(
        "users",
        sa.Column(
            "is_verified",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    # Extend the revoke_reason CHECK constraint to include the inactivity reason.
    op.execute(
        sa.text(
            f"ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS {_ENUM_CONSTRAINT}"
        )
    )
    op.create_check_constraint(
        _ENUM_CONSTRAINT,
        "refresh_tokens",
        f"revoke_reason IN ({', '.join(repr(v) for v in _NEW_REASONS)})",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(
        sa.text(
            f"ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS {_ENUM_CONSTRAINT}"
        )
    )
    op.create_check_constraint(
        _ENUM_CONSTRAINT,
        "refresh_tokens",
        f"revoke_reason IN ({', '.join(repr(v) for v in _OLD_REASONS)})",
    )
    op.drop_column("users", "is_verified")
    op.alter_column("users", "lockout_until", new_column_name="locked_until")
