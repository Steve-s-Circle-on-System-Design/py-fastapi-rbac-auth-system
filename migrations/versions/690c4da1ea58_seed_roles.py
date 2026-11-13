"""seed roles

Revision ID: 690c4da1ea58
Revises: 0d0ee94a8c95
Create Date: 2026-10-30 22:29:53.699972

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "690c4da1ea58"
down_revision: str | Sequence[str] | None = "0d0ee94a8c95"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
