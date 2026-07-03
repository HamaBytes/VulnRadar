"""add_osv_github_vendor_advisory_tables

Revision ID: ae944fd6caa9
Revises: 796faa5a2fcd
Create Date: 2026-07-02 19:45:23.855664

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ae944fd6caa9'
down_revision: Union[str, Sequence[str], None] = '796faa5a2fcd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # OSV records
    op.create_table(
        'osv_records',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('cve_db_id', sa.BigInteger(), nullable=False),
        sa.Column('cve_id', sa.String(length=50), nullable=False),
        sa.Column('osv_id', sa.String(length=100), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('severities', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['cve_db_id'], ['vulnradar.cves.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )

    op.create_table(
        'osv_references',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('osv_record_id', sa.BigInteger(), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('source_id', sa.String(length=255), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(['osv_record_id'], ['vulnradar.osv_records.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )

    # GitHub advisories
    op.create_table(
        'github_advisories',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('cve_db_id', sa.BigInteger(), nullable=False),
        sa.Column('cve_id', sa.String(length=50), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=True),
        sa.Column('package_name', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['cve_db_id'], ['vulnradar.cves.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )

    op.create_table(
        'github_advisory_references',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('github_advisory_id', sa.BigInteger(), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['github_advisory_id'], ['vulnradar.github_advisories.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )

    # Vendor advisories
    op.create_table(
        'vendor_advisories',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('cve_db_id', sa.BigInteger(), nullable=False),
        sa.Column('cve_id', sa.String(length=50), nullable=False),
        sa.Column('vendor', sa.String(length=100), nullable=True),
        sa.Column('is_available', sa.Boolean(), nullable=True),
        sa.Column('sources', sa.JSON(), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['cve_db_id'], ['vulnradar.cves.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='vulnradar'
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('vendor_advisories', schema='vulnradar')
    op.drop_table('github_advisory_references', schema='vulnradar')
    op.drop_table('github_advisories', schema='vulnradar')
    op.drop_table('osv_references', schema='vulnradar')
    op.drop_table('osv_records', schema='vulnradar')
