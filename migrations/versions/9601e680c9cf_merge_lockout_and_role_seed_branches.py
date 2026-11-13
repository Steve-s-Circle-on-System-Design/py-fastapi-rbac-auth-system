"""merge lockout and role seed branches

Revision ID: 9601e680c9cf
Revises: a16d22b701c4, c41e7b9a2d58
Create Date: 2026-11-02 12:07:28.119799

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9601e680c9cf'
down_revision: Union[str, Sequence[str], None] = ('a16d22b701c4', 'c41e7b9a2d58')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
