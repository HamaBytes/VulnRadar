"""APScheduler manager for VulnRadar.

Schedules and runs incremental database synchronization jobs in the background.
"""

import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from src.config.database import SessionLocal
from src.fetchers.pipelines import run_enrichment_pipeline
from src.services.Database.storage import DatabaseStorage

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
        
        Fetches the new/modified vulnerabilities, enriches them,
        and persists them to the database.
        """
        logger.info("Executing scheduled sync job...")
        try:
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
                return

            # 2. Persist to database using DatabaseStorage
            db = SessionLocal()
            try:
                storage = DatabaseStorage(db)
                saved_count = storage.save_enriched_cves(enriched_records)
                logger.info(f"Scheduled sync complete: Persisted {saved_count} records.")
            finally:
                db.close()

        except Exception as e:
            logger.error(f"Scheduled sync job failed: {e}", exc_info=True)

    def register_jobs(self) -> None:
        """Register the daily sync cron job (default runs daily at 2:00 AM)."""
        logger.info("Registering sync job...")
        
        # Add incremental sync job running daily at 2:00 AM
        self.scheduler.add_job(
            self.run_sync_job,
            trigger=CronTrigger(hour=2, minute=0),
            id="daily_incremental_sync",
            name="Daily incremental CVE synchronization",
            replace_existing=True,
        )
        
        logger.info("Daily incremental sync job scheduled for 02:00 AM.")
