"""Orchestrates all sync jobs in dependency order."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession

from src.sync.jobs.nvd_sync_job import NvdSyncJob

logger = logging.getLogger(__name__)


class FullSyncJob:
    """Runs complete sync pipeline: NVD → enrichments."""

    def __init__(self, db_session: AsyncSession, http_session: aiohttp.ClientSession):
        self.db = db_session
        self.http = http_session

    async def run_full(self, nvd_api_key: str | None = None) -> dict[str, Any]:
        """Run complete sync cycle."""
        results = {}

        # Phase 1: NVD incremental (core CVE data)
        logger.info("=== Phase 1: NVD Incremental Sync ===")
        nvd_job = NvdSyncJob(self.db, self.http, nvd_api_key)
        results["nvd"] = await nvd_job.run_incremental()

        # Phase 2: Enrichments (run concurrently)
        logger.info("=== Phase 2: Enrichment Sync ===")
        # TODO: Add EPSS, OSV, GitHub Advisory, Exploit fetchers
        # enrichment_results = await asyncio.gather(
        #     self._run_epss_sync(),
        #     self._run_osv_sync(),
        #     self._run_github_advisory_sync(),
        #     self._run_exploit_sync(),
        # )
        results["enrichments"] = {"status": "not_implemented"}

        return results

    async def run_historical_backfill(
            self,
            start_year: int = 1999,
            nvd_api_key: str | None = None,
    ) -> dict[str, Any]:
        """Run historical backfill from year to present."""
        from datetime import date

        start_date = date(start_year, 1, 1)
        end_date = date.today()

        nvd_job = NvdSyncJob(self.db, self.http, nvd_api_key)
        return await nvd_job.run_historical(start_date, end_date, chunk_days=30)