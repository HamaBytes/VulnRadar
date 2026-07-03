"""drop_unused_columns_and_tables

Revision ID: 20260702_drop_unused
Revises: ff12a3b4c5d6
Create Date: 2026-07-02 21:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20260702_drop_unused'
down_revision = 'ff12a3b4c5d6'
branch_labels = None
depends_on = None


def upgrade():
    # Drop columns that are unused (0 non-null)
    schema = 'vulnradar'
    # Drop exploit_references.module if it exists
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'vulnradar' AND table_name = 'exploit_references' AND column_name = 'module'
            ) THEN
                EXECUTE 'ALTER TABLE vulnradar.exploit_references DROP COLUMN module';
            END IF;
        END$$;
        """
    )

    # Drop cvss_data_v40.sub_* columns if they exist
    for col in ('sub_confidentiality_impact', 'sub_integrity_impact', 'sub_availability_impact'):
        op.execute(f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'vulnradar' AND table_name = 'cvss_data_v40' AND column_name = '{col}'
                ) THEN
                    EXECUTE 'ALTER TABLE vulnradar.cvss_data_v40 DROP COLUMN {col}';
                END IF;
            END$$;
        """)


def downgrade():
    schema = 'vulnradar'
    # Downgrade: re-create dropped columns/tables with permissive types
    with op.batch_alter_table('cvss_data_v40', schema=schema) as batch_op:
        batch_op.add_column(sa.Column('sub_confidentiality_impact', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('sub_integrity_impact', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('sub_availability_impact', sa.String(length=50), nullable=True))

    with op.batch_alter_table('exploit_references', schema=schema) as batch_op:
        batch_op.add_column(sa.Column('module', sa.String(length=500), nullable=True))
