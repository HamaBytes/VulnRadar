"""move tables to vulnradar schema

Revision ID: 9d7b8a4c2f10
Revises: 0462ac7a2236
Create Date: 2026-06-11 18:20:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = "9d7b8a4c2f10"
down_revision: Union[str, Sequence[str], None] = "0462ac7a2236"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


APP_TABLES = (
    "cves",
    "cve_tags",
    "cve_descriptions",
    "cvss_metric_v2",
    "cvss_data_v2",
    "cve_weaknesses",
    "cve_weakness_descriptions",
    "cve_configurations",
    "cve_nodes",
    "cpe_matches",
    "cve_references",
)


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("CREATE SCHEMA IF NOT EXISTS vulnradar")

    for table_name in APP_TABLES:
        op.execute(f"ALTER TABLE IF EXISTS public.{table_name} SET SCHEMA vulnradar")


def downgrade() -> None:
    """Downgrade schema."""
    for table_name in reversed(APP_TABLES):
        op.execute(f"ALTER TABLE IF EXISTS vulnradar.{table_name} SET SCHEMA public")

    op.execute("DROP SCHEMA IF EXISTS vulnradar")
