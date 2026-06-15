import logging
from datetime import datetime, date
from typing import Any, Optional, Callable

import aiohttp
from sqlalchemy import func

from src.fetchers.kev_fetcher_async import get_kev_cves
from src.services.enrichment import enrich_all_kevs
import src.config.database as db_config
import src.models.cves  # Ensure all ORM models are registered
from src.models.cve import Cve

logger = logging.getLogger(__name__)


async def run_enrichment_pipeline(
    limit: int | None = 10,
    include_epss: bool = True,
    include_nvd: bool = True,
    include_exploits: bool = True,
    incremental: bool = True,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> list[dict[str, Any]]:
    """Orchestrates the fetching of KEV vulnerabilities and enriching them
    with NVD, EPSS, and exploit-intelligence data.

    :param limit: Optional limit to restrict the number of KEVs processed.
    :param include_epss: Whether to enrich with EPSS scores.
    :param include_nvd: Whether to enrich with NVD data.
    :param include_exploits: Whether to enrich with exploit intelligence.
    :param incremental: Whether to only process KEVs newer than the latest CVE in DB.
    :param start_date: Optional start date to manually filter CISA dateAdded.
    :param end_date: Optional end date to manually filter CISA dateAdded.
    :param on_progress: Optional callback on_progress(current, total, stage).
    """
    async with aiohttp.ClientSession() as session:
        # Step 1: Fetch KEVs
        logger.info("Fetching KEV catalog...")
        kevs = await get_kev_cves(session)
        logger.info("Fetched %d KEV entries.", len(kevs))

        # Handle manual date range filtering if start_date is provided
        if start_date:
            logger.info(f"Performing manual sync range: {start_date} to {end_date or 'today'}")
            filtered_kevs = []
            for k in kevs:
                date_added_str = k.get("dateAdded")
                if date_added_str:
                    try:
                        date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date()
                        if date_added >= start_date:
                            if end_date and date_added > end_date:
                                continue
                            filtered_kevs.append(k)
                    except ValueError:
                        continue
            kevs = filtered_kevs
            logger.info(f"Filtered to %d KEV entries within the manual date range.", len(kevs))

        # Otherwise handle incremental DB filtering
        elif incremental:
            max_date = None
            try:
                db_config.init_db()
                db = db_config.SessionLocal()
                max_date = db.query(func.max(Cve.created_at)).scalar()
                db.close()
            except Exception as e:
                logger.warning(f"Could not retrieve last sync date for incremental sync: {e}. Performing full fetch.")

            if max_date:
                logger.info(f"Performing incremental sync since: {max_date}")
                max_date_only = max_date.date()
                filtered_kevs = []
                for k in kevs:
                    date_added_str = k.get("dateAdded")
                    if date_added_str:
                        try:
                            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date()
                            if date_added > max_date_only:
                                filtered_kevs.append(k)
                        except ValueError:
                            filtered_kevs.append(k)
                    else:
                        filtered_kevs.append(k)
                kevs = filtered_kevs
                logger.info(f"Filtered to %d KEV entries newer than latest database entry.", len(kevs))

        # Slicing the list if a limit is provided
        if limit is not None and limit > 0:
            kevs = kevs[:limit]
            logger.info("Limited to %d KEV entries for processing.", len(kevs))

        # Step 2: Enrich with NVD + EPSS + Exploit data
        enriched_kevs = await enrich_all_kevs(
            kevs,
            session,
            max_concurrent=1,
            include_epss=include_epss,
            include_nvd=include_nvd,
            include_exploits=include_exploits,
            on_progress=on_progress,
        )

        return enriched_kevs
