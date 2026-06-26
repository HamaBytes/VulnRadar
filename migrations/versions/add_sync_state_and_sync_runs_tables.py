"""add sync_state and sync_runs tables

Revision ID: add_sync_state_and_sync_runs
Revises: 0462ac7a2236
Create Date: 2026-06-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'add_sync_state_and_sync_runs'
down_revision: Union[str, Sequence[str], None] = 'c331ef333319'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "sync_state",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("sync_type", sa.String(length=50), nullable=False),
        sa.Column("last_modified_watermark", sa.DateTime(), nullable=True),
        sa.Column("last_sync_date", sa.DateTime(), nullable=True),
        sa.Column("is_syncing", sa.Boolean(), nullable=True, default=False),
        sa.Column("status", sa.String(length=50), nullable=True, default="idle"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sync_type"),
        schema="vulnradar"
    )
    
    op.create_table(
        "sync_runs",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("sync_state_id", sa.BigInteger(), nullable=False),
        sa.Column("run_type", sa.String(length=50), nullable=False),
        sa.Column("start_date", sa.DateTime(), nullable=False),
        sa.Column("end_date", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=True, default="pending"),
        sa.Column("records_processed", sa.BigInteger(), nullable=True, default=0),
        sa.Column("records_saved", sa.BigInteger(), nullable=True, default=0),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["sync_state_id"], ["vulnradar.sync_state.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="vulnradar"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("sync_runs", schema="vulnradar")
    op.drop_table("sync_state", schema="vulnradar")
