"""Add refresh-token rotation and revocation metadata.

Revision ID: a1b2c3d4e5f6
Revises: cfa269117122
Create Date: 2026-07-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "cfa269117122"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "refresh_tokens",
        sa.Column("token_family", sa.String(length=255), nullable=True),
    )
    # Legacy rows are made their own family before enforcing the invariant.
    op.execute(
        "UPDATE refresh_tokens SET token_family = id::text WHERE token_family IS NULL"
    )
    op.alter_column("refresh_tokens", "token_family", nullable=False)
    op.create_index(
        "ix_refresh_tokens_token_family",
        "refresh_tokens",
        ["token_family"],
        unique=False,
    )
    op.add_column(
        "refresh_tokens", sa.Column("parent_token_id", sa.UUID(), nullable=True)
    )
    op.create_foreign_key(
        "fk_refresh_tokens_parent_token_id",
        "refresh_tokens",
        "refresh_tokens",
        ["parent_token_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column(
        "refresh_tokens", sa.Column("ip_address", sa.String(length=45), nullable=True)
    )
    op.add_column("refresh_tokens", sa.Column("user_agent", sa.Text(), nullable=True))
    op.add_column(
        "refresh_tokens",
        sa.Column("revoke_reason", sa.String(length=50), nullable=True),
    )
    op.add_column(
        "refresh_tokens",
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "refresh_tokens",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("TIMEZONE('utc', now())"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("refresh_tokens", "created_at")
    op.drop_column("refresh_tokens", "revoked_at")
    op.drop_column("refresh_tokens", "revoke_reason")
    op.drop_column("refresh_tokens", "user_agent")
    op.drop_column("refresh_tokens", "ip_address")
    op.drop_constraint(
        "fk_refresh_tokens_parent_token_id", "refresh_tokens", type_="foreignkey"
    )
    op.drop_column("refresh_tokens", "parent_token_id")
    op.drop_index("ix_refresh_tokens_token_family", table_name="refresh_tokens")
    op.drop_column("refresh_tokens", "token_family")
