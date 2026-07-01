import logging
from datetime import datetime, date, timedelta
import socket
from typing import Any, Optional, Callable

import aiohttp
from sqlalchemy import func

from src.fetchers.kev_fetcher_async import get_kev_cves
from src.fetchers.nvd_fetcher_async import fetch_vulnerabilities_flat
from src.services.enrichment import enrich_all_kevs
from src.config.database import DatabaseConnector, db_session_ro, init_db
import src.models.cves  # Ensure all ORM models are registered
from src.models.cve import Cve
from src.models.sync_state import SyncState, SyncRun

logger = logging.getLogger(__name__)


async def run_enrichment_pipeline(
    limit: int | None = 10,
    include_epss: bool = True,
    include_nvd: bool = True,
    include_exploits: bool = True,
    include_osv: bool = True,
    include_github_advisories: bool = True,
    include_vendor_advisories: bool = True,
    incremental: bool = True,
    last_modified_watermark: Optional[datetime] = None,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> list[dict[str, Any]]:
    """Orchestrates the fetching of KEV vulnerabilities and enriching them
    with NVD, EPSS, exploit-intelligence, OSV, GitHub Advisory, and vendor
    advisory data.

    :param limit: Optional limit to restrict the number of KEVs processed.
    :param include_epss: Whether to enrich with EPSS scores.
    :param include_nvd: Whether to enrich with NVD data.
    :param include_exploits: Whether to enrich with exploit intelligence.
    :param include_osv: Whether to enrich with OSV metadata.
    :param include_github_advisories: Whether to enrich with GitHub Advisory metadata.
    :param include_vendor_advisories: Whether to enrich with vendor advisory metadata.
    :param incremental: Whether to only process KEVs newer than the latest CVE in DB.
    :param start_date: Optional start date to manually filter CISA dateAdded.
    :param end_date: Optional end date to manually filter CISA dateAdded.
    :param on_progress: Optional callback on_progress(current, total, stage).
    """
    connector = aiohttp.TCPConnector(family=socket.AF_INET, resolver=aiohttp.ThreadedResolver())
    async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
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
            max_date = last_modified_watermark
            try:
                init_db()
                with db_session_ro() as db:
                    if max_date is None:
                        max_date = db.query(func.max(Cve.last_modified_date)).scalar()
            except Exception as e:
                logger.warning(f"Could not retrieve last sync date for incremental sync: {e}. Performing full fetch.")
            if max_date:
                logger.info(f"Performing incremental sync since: {max_date}")
                max_date_only = max_date.date() if isinstance(max_date, datetime) else max_date
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
            include_osv=True,
            include_github_advisories=True,
            include_vendor_advisories=True,
            on_progress=on_progress,
        )

        return enriched_kevs


async def run_historical_import(
    start_date: date,
    end_date: Optional[date] = None,
    chunk_days: int = 30,
    include_epss: bool = True,
    include_nvd: bool = True,
    include_exploits: bool = True,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
) -> dict[str, Any]:
    """Run historical NVD CVE import in 30-day chunks with resumable cursor.
    
    :param start_date: Start date for historical import (e.g., date(2023, 1, 1))
    :param end_date: End date for historical import (defaults to today)
    :param chunk_days: Number of days per chunk (default 30)
    :param include_epss: Whether to enrich with EPSS scores
    :param include_nvd: Whether to enrich with NVD data
    :param include_exploits: Whether to enrich with exploit intelligence
    :param on_progress: Optional callback on_progress(current, total, stage)
    :return: Dictionary with import statistics
    """
    if end_date is None:
        end_date = date.today()
    
    init_db()
    db = DatabaseConnector().create_session()
    try:
        # Get or create sync state for NVD historical import
        sync_state = db.query(SyncState).filter(SyncState.sync_type == "nvd_historical").first()
        if not sync_state:
            sync_state = SyncState(
                sync_type="nvd_historical",
                status="idle",
            )
            db.add(sync_state)
            db.flush()
        
        # Check if there's a pending run to resume from
        last_run = db.query(SyncRun).filter(
            SyncRun.sync_state_id == sync_state.id,
            SyncRun.status == "pending"
        ).order_by(SyncRun.start_date).first()
        
        if last_run:
            logger.info(f"Resuming from pending run: {last_run.start_date} to {last_run.end_date}")
            current_start = last_run.start_date.date()
        else:
            current_start = start_date
        
        # Calculate total chunks
        total_days = (end_date - start_date).days
        total_chunks = (total_days + chunk_days - 1) // chunk_days
        
        logger.info(f"Starting historical import: {start_date} to {end_date} ({total_days} days, {total_chunks} chunks)")
        
        total_cves = 0
        total_saved = 0
        chunk_count = 0
        
        connector = aiohttp.TCPConnector(family=socket.AF_INET, resolver=aiohttp.ThreadedResolver())
        async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
            while current_start < end_date:
                chunk_end = min(current_start + timedelta(days=chunk_days), end_date)
                
                # Check if this chunk was already completed
                existing_run = db.query(SyncRun).filter(
                    SyncRun.sync_state_id == sync_state.id,
                    SyncRun.start_date == datetime.combine(current_start, datetime.min.time()),
                    SyncRun.end_date == datetime.combine(chunk_end, datetime.min.time()),
                    SyncRun.status == "completed"
                ).first()
                
                if existing_run:
                    logger.info(f"Skipping completed chunk: {current_start} to {chunk_end}")
                    total_cves += existing_run.records_processed or 0
                    total_saved += existing_run.records_saved or 0
                    current_start = chunk_end
                    chunk_count += 1
                    if on_progress:
                        on_progress(chunk_count, total_chunks, f"Skipping completed chunk {chunk_count}/{total_chunks}")
                    continue
                
                # Create sync run for this chunk
                sync_run = SyncRun(
                    sync_state_id=sync_state.id,
                    run_type="historical_30day_chunk",
                    start_date=datetime.combine(current_start, datetime.min.time()),
                    end_date=datetime.combine(chunk_end, datetime.min.time()),
                    status="running",
                    started_at=datetime.utcnow(),
                )
                db.add(sync_run)
                db.flush()
                
                logger.info(f"Processing chunk {chunk_count + 1}/{total_chunks}: {current_start} to {chunk_end}")
                if on_progress:
                    on_progress(chunk_count + 1, total_chunks, f"Fetching NVD data for {current_start} to {chunk_end}")
                
                # Format dates for NVD API (ISO 8601)
                last_modified_start = current_start.strftime("%Y-%m-%dT00:00:00.000")
                last_modified_end = chunk_end.strftime("%Y-%m-%dT23:59:59.999")
                
                try:
                    # Fetch NVD vulnerabilities for this date range
                    nvd_data = await fetch_vulnerabilities_flat(
                        session,
                        max_results=10000,  # High limit for historical import
                        last_modified_start=last_modified_start,
                        last_modified_end=last_modified_end,
                    )
                    
                    logger.info(f"Fetched {len(nvd_data)} NVD CVEs for chunk {current_start} to {chunk_end}")
                    sync_run.records_processed = len(nvd_data)
                    
                    # Convert NVD data to enriched format
                    enriched_records = []
                    for nvd_item in nvd_data:
                        # nvd_item is an NvdVulnerability object with a cve attribute
                        cve = nvd_item.cve
                        cve_id = cve.cve_id
                        
                        if not cve_id:
                            continue
                        
                        # Get description
                        description = ""
                        if cve.descriptions:
                            description = cve.descriptions[0].value
                        
                        # Create basic enriched record structure
                        enriched_record = {
                            "cveID": cve_id,
                            "vulnerabilityName": description,
                            "nvd_published": cve.published,
                            "nvd_last_modified": cve.last_modified,
                            "nvd_vuln_status": cve.vuln_status,
                            "nvd_cve_obj": cve,  # Pass the full NvdCve object
                        }
                        enriched_records.append(enriched_record)
                    
                    # Save to database
                    from src.services.Database.storage import DatabaseStorage
                    storage = DatabaseStorage(db)
                    saved_count = storage.save_enriched_cves(enriched_records)
                    
                    sync_run.records_saved = saved_count
                    sync_run.status = "completed"
                    sync_run.completed_at = datetime.utcnow()
                    
                    total_cves += len(nvd_data)
                    total_saved += saved_count
                    
                    logger.info(f"Chunk complete: {current_start} to {chunk_end}, fetched {len(nvd_data)}, saved {saved_count}")
                    
                except Exception as e:
                    logger.error(f"Failed to process chunk {current_start} to {chunk_end}: {e}")
                    sync_run.status = "failed"
                    sync_run.error_message = str(e)
                    sync_run.completed_at = datetime.utcnow()
                    db.commit()
                    raise
                
                finally:
                    db.commit()
                
                current_start = chunk_end
                chunk_count += 1
        
        # Update sync state
        sync_state.last_sync_date = datetime.utcnow()
        sync_state.status = "completed"
        sync_state.is_syncing = False
        db.commit()
        
        logger.info(f"Historical import complete: {total_cves} CVEs fetched, {total_saved} saved")
        
        return {
            "total_cves_fetched": total_cves,
            "total_cves_saved": total_saved,
            "total_chunks": chunk_count,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        }
        
    finally:
        db.close()
