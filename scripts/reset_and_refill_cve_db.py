#!/usr/bin/env python3
import asyncio
import logging
import os
import sys

# Ensure repo root is on sys.path when the script is executed directly
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from sqlalchemy import text

from src.config.database import DatabaseConnector, init_db
from src.fetchers.pipelines import run_enrichment_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TRUNCATE_SQL = text(
    """
    TRUNCATE TABLE
        vulnradar.vendor_advisories,
        vulnradar.github_advisory_references,
        vulnradar.github_advisories,
        vulnradar.osv_references,
        vulnradar.osv_records,
        vulnradar.exploit_references,
        vulnradar.epss,
        vulnradar.cve_references,
        vulnradar.cve_descriptions,
        vulnradar.cve_tags,
        vulnradar.cve_weakness_descriptions,
        vulnradar.cve_weaknesses,
        vulnradar.cpe_matches,
        vulnradar.cve_nodes,
        vulnradar.cve_configurations,
        vulnradar.cves,
        vulnradar.sync_runs,
        vulnradar.sync_state
    RESTART IDENTITY CASCADE;
    """
)


def truncate_cve_data() -> None:
    init_db()
    engine = DatabaseConnector().engine
    logging.info("Truncating CVE and enrichment tables...")
    with engine.begin() as conn:
        conn.execute(TRUNCATE_SQL)
    logging.info("Truncate complete.")


async def refill_cve_data() -> None:
    logging.info("Running enrichment pipeline to refill CVE data...")
    records = await run_enrichment_pipeline(
        limit=None,
        include_epss=True,
        include_nvd=True,
        include_exploits=True,
        include_osv=True,
        include_github_advisories=True,
        include_vendor_advisories=True,
        incremental=False,
    )
    logging.info("Refill completed. Enriched records: %d", len(records))


def main() -> None:
    truncate_cve_data()
    asyncio.run(refill_cve_data())


if __name__ == "__main__":
    main()
