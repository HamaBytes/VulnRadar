"""create cves table

Revision ID: 0462ac7a2236
Revises: b8d5f16225b0
Create Date: 2026-06-11 17:48:53.042933

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0462ac7a2236'
down_revision: Union[str, Sequence[str], None] = 'b8d5f16225b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("cves", sa.Column("source_identifier", sa.String(length=255), nullable=True))
    op.add_column("cves", sa.Column("last_modified_date", sa.DateTime(), nullable=True))
    op.add_column("cves", sa.Column("vuln_status", sa.String(length=50), nullable=True))
    op.alter_column("cves", "title", existing_type=sa.String(length=500), nullable=True)
    op.alter_column("cves", "cvss_v3_score", existing_type=sa.DECIMAL(precision=3, scale=2), type_=sa.DECIMAL(precision=4, scale=1))

    op.create_table(
        "cve_tags",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("cve_db_id", sa.BigInteger(), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(["cve_db_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cve_descriptions",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("cve_db_id", sa.BigInteger(), nullable=False),
        sa.Column("lang", sa.String(length=10), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["cve_db_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cvss_metric_v2",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("cve_db_id", sa.BigInteger(), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=True),
        sa.Column("metric_type", sa.String(length=50), nullable=True),
        sa.Column("base_severity", sa.String(length=20), nullable=True),
        sa.Column("exploitability_score", sa.DECIMAL(precision=4, scale=1), nullable=True),
        sa.Column("impact_score", sa.DECIMAL(precision=4, scale=1), nullable=True),
        sa.Column("ac_insuf_info", sa.Boolean(), nullable=True),
        sa.Column("obtain_all_privilege", sa.Boolean(), nullable=True),
        sa.Column("obtain_user_privilege", sa.Boolean(), nullable=True),
        sa.Column("obtain_other_privilege", sa.Boolean(), nullable=True),
        sa.Column("user_interaction_required", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["cve_db_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cve_weaknesses",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("cve_db_id", sa.BigInteger(), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=True),
        sa.Column("weakness_type", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(["cve_db_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cve_configurations",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("cve_db_id", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(["cve_db_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cve_references",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("cve_db_id", sa.BigInteger(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["cve_db_id"], ["cves.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cvss_data_v2",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("metric_id", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.String(length=20), nullable=True),
        sa.Column("vector_string", sa.String(length=255), nullable=True),
        sa.Column("base_score", sa.DECIMAL(precision=4, scale=1), nullable=True),
        sa.Column("access_vector", sa.String(length=50), nullable=True),
        sa.Column("access_complexity", sa.String(length=50), nullable=True),
        sa.Column("authentication", sa.String(length=50), nullable=True),
        sa.Column("confidentiality_impact", sa.String(length=50), nullable=True),
        sa.Column("integrity_impact", sa.String(length=50), nullable=True),
        sa.Column("availability_impact", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(["metric_id"], ["cvss_metric_v2.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("metric_id"),
    )
    op.create_table(
        "cve_weakness_descriptions",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("weakness_id", sa.BigInteger(), nullable=False),
        sa.Column("lang", sa.String(length=10), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["weakness_id"], ["cve_weaknesses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cve_nodes",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("configuration_id", sa.BigInteger(), nullable=False),
        sa.Column("operator", sa.String(length=20), nullable=True),
        sa.Column("negate", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["configuration_id"], ["cve_configurations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cpe_matches",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("node_id", sa.BigInteger(), nullable=False),
        sa.Column("vulnerable", sa.Boolean(), nullable=True),
        sa.Column("criteria", sa.Text(), nullable=True),
        sa.Column("match_criteria_id", sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(["node_id"], ["cve_nodes.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("cpe_matches")
    op.drop_table("cve_nodes")
    op.drop_table("cve_weakness_descriptions")
    op.drop_table("cvss_data_v2")
    op.drop_table("cve_references")
    op.drop_table("cve_configurations")
    op.drop_table("cve_weaknesses")
    op.drop_table("cvss_metric_v2")
    op.drop_table("cve_descriptions")
    op.drop_table("cve_tags")
    op.alter_column("cves", "cvss_v3_score", existing_type=sa.DECIMAL(precision=4, scale=1), type_=sa.DECIMAL(precision=3, scale=2))
    op.alter_column("cves", "title", existing_type=sa.String(length=500), nullable=False)
    op.drop_column("cves", "vuln_status")
    op.drop_column("cves", "last_modified_date")
    op.drop_column("cves", "source_identifier")
