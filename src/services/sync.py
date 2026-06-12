"""Integration and Sync Orchestration Service."""

import logging
from typing import Any

import aiohttp

from src.services.kev_fetcher_async import get_kev_cves
from src.services.enrichment import enrich_all_kevs

logger = logging.getLogger(__name__)


async def run_enrichment_pipeline(
    limit: int | None = 10,
    include_epss: bool = True,
    include_nvd: bool = True,
) -> list[dict[str, Any]]:
    """
    Orchestrates the fetching of KEV vulnerabilities and enriching them
    with NVD + EPSS data.

    :param limit: Optional limit to restrict the number of KEVs processed
                  (helps avoid NVD rate-limit bans during testing).
    :param include_epss: Whether to enrich with EPSS scores (bulk CSV download).
    :param include_nvd: Whether to enrich with NVD data (per-CVE API calls).
    """
    async with aiohttp.ClientSession() as session:
        # Step 1: Fetch KEVs
        logger.info("Fetching KEV catalog...")
        kevs = await get_kev_cves(session)
        logger.info("Fetched %d KEV entries.", len(kevs))

        # Slicing the list if a limit is provided
        if limit is not None and limit > 0:
            kevs = kevs[:limit]
            logger.info("Limited to %d KEV entries for processing.", len(kevs))

        # Step 2: Enrich with NVD + EPSS data
        enriched_kevs = await enrich_all_kevs(
            kevs,
            session,
            max_concurrent=1,
            include_epss=include_epss,
            include_nvd=include_nvd,
        )

        return enriched_kevs
