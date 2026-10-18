"""High-level pipeline entry points."""

from __future__ import annotations

import logging

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession
from src.sync.jobs.full_sync_job import FullSyncJob
from src.sync.jobs.nvd_sync_job import NvdSyncJob

logger = logging.getLogger(__name__)


async def run_incremental_sync(
        db_session: AsyncSession,
        http_session: aiohttp.ClientSession,
        nvd_api_key: str | None = None,
) -> dict[str, any]:
    """Run incremental sync — called by scheduler/cron."""
    job = FullSyncJob(db_session, http_session)
    return await job.run_full(nvd_api_key)


async def run_historical_sync(
        db_session: AsyncSession,
        http_session: aiohttp.ClientSession,
        start_year: int = 1999,
        nvd_api_key: str | None = None,
) -> dict[str, any]:
    """Run historical backfill — called once for initial population."""
    job = FullSyncJob(db_session, http_session)
    return await job.run_historical_backfill(start_year, nvd_api_key)


async def run_kev_enrichment(
        db_session: AsyncSession,
        http_session: aiohttp.ClientSession,
) -> dict[str, any]:
    """Enrich existing CVEs with KEV data."""
    from src.fetchers.kev_fetcher import KevFetcher
    from src.sync.importer import CveBulkImporter

    fetcher = KevFetcher(http_session)
    importer = CveBulkImporter(db_session)

    kevs = await fetcher.fetch_all()
    records = [fetcher.transform(k) for k in kevs]

    if records:
        # KEV records need to be merged with existing CVEs
        # The importer handles upsert
        count = await importer.process_enriched_records(records)
        await db_session.commit()
        return {"kev_count": len(kevs), "saved": count}

    return {"kev_count": 0, "saved": 0}