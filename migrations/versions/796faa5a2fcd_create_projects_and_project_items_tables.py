"""create projects and project_items tables

Revision ID: 796faa5a2fcd
Revises: add_sync_state_and_sync_runs
Create Date: 2026-06-30 07:54:11.633454

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '796faa5a2fcd'
down_revision: Union[str, Sequence[str], None] = 'add_sync_state_and_sync_runs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
