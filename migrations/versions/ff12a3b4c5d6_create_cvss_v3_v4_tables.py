"""create_cvss_v3_v4_tables

Revision ID: ff12a3b4c5d6
Revises: ae944fd6caa9
Create Date: 2026-07-02 20:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ff12a3b4c5d6'
down_revision: Union[str, Sequence[str], None] = 'ae944fd6caa9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # CVSS v3.1 metric + data
    op.create_table(
        'cvss_metric_v31',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('cve_db_id', sa.BigInteger(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=True),
        sa.Column('metric_type', sa.String(length=50), nullable=True),
        sa.Column('exploitability_score', sa.DECIMAL(4, 1), nullable=True),
        sa.Column('impact_score', sa.DECIMAL(4, 1), nullable=True),
        sa.ForeignKeyConstraint(['cve_db_id'], ['vulnradar.cves.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )

    op.create_table(
        'cvss_data_v31',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('metric_id', sa.BigInteger(), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=True),
        sa.Column('vector_string', sa.String(length=255), nullable=True),
        sa.Column('base_score', sa.DECIMAL(4, 1), nullable=True),
        sa.Column('base_severity', sa.String(length=20), nullable=True),
        sa.Column('attack_vector', sa.String(length=50), nullable=True),
        sa.Column('attack_complexity', sa.String(length=50), nullable=True),
        sa.Column('privileges_required', sa.String(length=50), nullable=True),
        sa.Column('user_interaction', sa.String(length=50), nullable=True),
        sa.Column('scope', sa.String(length=50), nullable=True),
        sa.Column('confidentiality_impact', sa.String(length=50), nullable=True),
        sa.Column('integrity_impact', sa.String(length=50), nullable=True),
        sa.Column('availability_impact', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['metric_id'], ['vulnradar.cvss_metric_v31.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )

    # CVSS v4.0 metric + data
    op.create_table(
        'cvss_metric_v40',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('cve_db_id', sa.BigInteger(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=True),
        sa.Column('metric_type', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['cve_db_id'], ['vulnradar.cves.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )

    op.create_table(
        'cvss_data_v40',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('metric_id', sa.BigInteger(), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=True),
        sa.Column('vector_string', sa.String(length=255), nullable=True),
        sa.Column('base_score', sa.DECIMAL(4, 1), nullable=True),
        sa.Column('base_severity', sa.String(length=20), nullable=True),
        sa.Column('attack_vector', sa.String(length=50), nullable=True),
        sa.Column('attack_complexity', sa.String(length=50), nullable=True),
        sa.Column('attack_requirements', sa.String(length=50), nullable=True),
        sa.Column('privileges_required', sa.String(length=50), nullable=True),
        sa.Column('user_interaction', sa.String(length=50), nullable=True),
        sa.Column('vuln_confidentiality_impact', sa.String(length=50), nullable=True),
        sa.Column('vuln_integrity_impact', sa.String(length=50), nullable=True),
        sa.Column('vuln_availability_impact', sa.String(length=50), nullable=True),
        sa.Column('sub_confidentiality_impact', sa.String(length=50), nullable=True),
        sa.Column('sub_integrity_impact', sa.String(length=50), nullable=True),
        sa.Column('sub_availability_impact', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['metric_id'], ['vulnradar.cvss_metric_v40.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('cvss_data_v40', schema='vulnradar')
    op.drop_table('cvss_metric_v40', schema='vulnradar')
    op.drop_table('cvss_data_v31', schema='vulnradar')
    op.drop_table('cvss_metric_v31', schema='vulnradar')
