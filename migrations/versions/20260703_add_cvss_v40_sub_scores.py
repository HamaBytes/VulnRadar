"""add_cvss_v40_sub_scores

Revision ID: 20260703_add_cvss_v40_sub_scores
Revises: 20260702_drop_unused
Create Date: 2026-07-03 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20260703_add_cvss_v40_sub_scores'
down_revision = '20260702_drop_unused'
branch_labels = None
depends_on = None


def upgrade():
    schema = 'vulnradar'
    op.execute(
        """
        ALTER TABLE vulnradar.cvss_data_v40
        ADD COLUMN IF NOT EXISTS sub_confidentiality_impact FLOAT NULL,
        ADD COLUMN IF NOT EXISTS sub_integrity_impact FLOAT NULL,
        ADD COLUMN IF NOT EXISTS sub_availability_impact FLOAT NULL;
        """
    )


def downgrade():
    schema = 'vulnradar'
    op.execute(
        """
        ALTER TABLE vulnradar.cvss_data_v40
        DROP COLUMN IF EXISTS sub_confidentiality_impact,
        DROP COLUMN IF EXISTS sub_integrity_impact,
        DROP COLUMN IF EXISTS sub_availability_impact;
        """
    )
