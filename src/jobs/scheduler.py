"""APScheduler manager for VulnRadar.

Schedules and runs incremental database synchronization jobs in the background.
"""

import logging
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from src.config.database import SessionLocal
from src.fetchers.pipelines import run_enrichment_pipeline
from src.services.Database.storage import DatabaseStorage
from src.models.sync_state import SyncState

logger = logging.getLogger(__name__)


class SchedulerManager:
    """Manages background job scheduling and lifecycle hooks."""

    def __init__(self) -> None:
        """Initialize the AsyncIO Scheduler."""
        self.scheduler = AsyncIOScheduler()

    def start(self) -> None:
        """Start the background scheduler."""
        if not self.scheduler.running:
            logger.info("Starting background scheduler...")
            self.scheduler.start()

    def shutdown(self) -> None:
        """Shutdown the background scheduler."""
        if self.scheduler.running:
            logger.info("Stopping background scheduler...")
            self.scheduler.shutdown()

    async def run_sync_job(self) -> None:
        """Execute the incremental synchronization job.
        
        Fetches the new/modified vulnerabilities using lastModified watermark,
        enriches them, and persists them to the database.
        """
        logger.info("Executing scheduled sync job...")
        db = SessionLocal()
        try:
            # Get sync state for incremental sync
            sync_state = db.query(SyncState).filter(SyncState.sync_type == "nvd_incremental").first()
            if not sync_state:
                sync_state = SyncState(
                    sync_type="nvd_incremental",
                    status="idle",
                )
                db.add(sync_state)
                db.flush()
            
            # Get lastModified watermark
            last_modified_watermark = sync_state.last_modified_watermark
            if last_modified_watermark:
                logger.info(f"Using lastModified watermark: {last_modified_watermark}")
            else:
                logger.info("No lastModified watermark found, performing initial sync")
                last_modified_watermark = datetime(2023, 1, 1)  # Default to 2023 if no watermark
            
            # Update sync state to running
            sync_state.is_syncing = True
            sync_state.status = "running"
            db.commit()
            
            # 1. Run enrichment pipeline incrementally
            enriched_records = await run_enrichment_pipeline(
                limit=None,  # Sync all new KEVs
                include_epss=True,
                include_nvd=True,
                include_exploits=True,
                incremental=True,
            )

            if not enriched_records:
                logger.info("Scheduled sync complete: No new records to save.")
                sync_state.is_syncing = False
                sync_state.status = "completed"
                sync_state.last_sync_date = datetime.utcnow()
                db.commit()
                return

            # 2. Persist to database using DatabaseStorage
            storage = DatabaseStorage(db)
            saved_count = storage.save_enriched_cves(enriched_records)
            
            # Update sync state with new watermark
            sync_state.last_modified_watermark = datetime.utcnow()
            sync_state.last_sync_date = datetime.utcnow()
            sync_state.is_syncing = False
            sync_state.status = "completed"
            db.commit()
            
            logger.info(f"Scheduled sync complete: Persisted {saved_count} records. Updated watermark to {sync_state.last_modified_watermark}")
            
        except Exception as e:
            logger.error(f"Scheduled sync job failed: {e}", exc_info=True)
            if sync_state:
                sync_state.is_syncing = False
                sync_state.status = "failed"
                sync_state.error_message = str(e)
                db.commit()
        finally:
            db.close()

    def register_jobs(self) -> None:
        """Register the daily sync cron job (runs daily at 03:00 UTC)."""

        logger.info("Registering sync job...")
        
        # Add incremental sync job running daily at 03:00 UTC
        self.scheduler.add_job(
            self.run_sync_job,
            trigger=CronTrigger(hour=3, minute=0, timezone='UTC'),
            id="daily_incremental_sync",
            name="Daily incremental CVE synchronization",
            replace_existing=True,
        )
        
        logger.info("Daily incremental sync job scheduled for 03:00 UTC.")
