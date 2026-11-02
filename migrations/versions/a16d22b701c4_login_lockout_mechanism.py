"""login lockout mechanism

Revision ID: a16d22b701c4
Revises: ba468afbb3c6
Create Date: 2026-09-25 12:51:59.631460

The schema changes from this migration are already represented by the baseline
revision. Keep this revision as a no-op to preserve the existing revision graph.
"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "a16d22b701c4"
down_revision: str | Sequence[str] | None = "ba468afbb3c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """The schema is already present in the baseline revision."""


def downgrade() -> None:
    """No changes were applied by this compatibility revision."""
