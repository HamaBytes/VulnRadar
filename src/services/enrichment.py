"""Enrichment service.

Enriches KEV vulnerability records with data from NVD and EPSS sources.
"""

import asyncio
import logging
from typing import Any

import aiohttp

from src.services.nvd_fetcher_async import fetch_page
from src.services.epss_fetcher_async import download_epss_scores, enrich_records_with_epss

logger = logging.getLogger(__name__)


async def enrich_vulnerability_with_nvd(
    kev_record: dict[str, Any],
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    """Enrich a single KEV record with NVD data."""
    cve_id = kev_record.get("cveID")
    if not cve_id:
        return kev_record

    async with semaphore:
        try:
            # Without API key, NVD restricts requests to 5 per 30 seconds.
            # Add a delay to prevent 403 Forbidden rate limit errors.
            await asyncio.sleep(6.5)

            nvd_resp = await fetch_page(session, cve_id=cve_id)
            if nvd_resp and nvd_resp.vulnerabilities:
                nvd_cve = nvd_resp.vulnerabilities[0].cve
                # Merge relevant NVD data into the KEV record
                kev_record["nvd_published"] = nvd_cve.published
                kev_record["nvd_last_modified"] = nvd_cve.last_modified
                kev_record["nvd_vuln_status"] = nvd_cve.vuln_status

                # Extract best available CVSS score (v4.0 > v3.1 > v2)
                base_score, base_severity, cvss_version = nvd_cve.best_score()
                kev_record["nvd_base_score"] = base_score
                kev_record["nvd_base_severity"] = base_severity
                kev_record["nvd_cvss_version"] = cvss_version
        except Exception as e:
            # Log error and continue to not break the pipeline
            logger.warning("NVD enrichment failed for %s: %s", cve_id, e)
            kev_record["nvd_enrichment_error"] = str(e)

    return kev_record


async def enrich_all_kevs(
    kevs: list[dict[str, Any]],
    session: aiohttp.ClientSession,
    max_concurrent: int = 1,
    include_epss: bool = True,
    include_nvd: bool = True,
) -> list[dict[str, Any]]:
    """
    Full enrichment pipeline: enriches KEV records with NVD + EPSS data.

    :param kevs: List of KEV vulnerability dicts.
    :param session: Shared aiohttp ClientSession.
    :param max_concurrent: Max concurrent NVD requests (1 = sequential, safe for no API key).
    :param include_epss: Whether to enrich with EPSS scores.
    :param include_nvd: Whether to enrich with NVD data.
    """
    # --- Step 1: EPSS enrichment (bulk download, fast) ---
    if include_epss:
        try:
            logger.info("Downloading EPSS scores for bulk enrichment...")
            epss_lookup = await download_epss_scores(session)
            kevs = enrich_records_with_epss(kevs, epss_lookup)
            logger.info("EPSS enrichment completed for %d records.", len(kevs))
        except Exception as e:
            logger.warning("EPSS enrichment failed: %s", e)
            # Mark all records with null EPSS if bulk download failed
            for kev in kevs:
                kev["epss_score"] = None
                kev["epss_percentile"] = None

    # --- Step 2: NVD enrichment (per-CVE API calls, slow) ---
    if include_nvd:
        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = [enrich_vulnerability_with_nvd(kev, session, semaphore) for kev in kevs]
        kevs = list(await asyncio.gather(*tasks))

    return kevs
