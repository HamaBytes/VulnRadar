"""NVD historical and incremental sync job."""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from src.fetchers.nvd_fetcher import NvdFetcher
from src.sync.importer import CveBulkImporter
from src.models.sync_state import SyncState, SyncRun

logger = logging.getLogger(__name__)


class NvdSyncJob:
    """Orchestrates NVD CVE import with resumable chunked execution."""

    def __init__(self, session: AsyncSession, http_session, api_key: str | None = None):
        self.db = session
        self.fetcher = NvdFetcher(http_session, api_key)
        self.importer = CveBulkImporter(session)

    async def run_incremental(self) -> dict[str, int]:
        """Fetch CVEs modified since last sync."""
        # Get watermark
        sync_state = await self._get_or_create_sync_state("nvd_incremental")
        watermark = sync_state.last_modified_watermark

        since = watermark.isoformat() if watermark else None
        logger.info(f"NVD incremental sync from {since or 'beginning'}")

        # Fetch
        vulnerabilities = await self.fetcher.fetch_incremental(since=since)

        # Transform
        records = [self.fetcher.transform(v) for v in vulnerabilities]

        # Import
        if records:
            count = await self.importer.process_enriched_records(records)
            await self.db.commit()

            # Update watermark
            sync_state.last_modified_watermark = datetime.utcnow()
            sync_state.last_sync_date = datetime.utcnow()
            sync_state.status = "completed"
            await self.db.commit()

            return {"fetched": len(vulnerabilities), "saved": count}

        return {"fetched": 0, "saved": 0}

    async def run_historical(
            self,
            start_date: date,
            end_date: date | None = None,
            chunk_days: int = 30,
    ) -> dict[str, int]:
        """Run historical sync in resumable date chunks."""
        end_date = end_date or date.today()

        sync_state = await self._get_or_create_sync_state("nvd_historical")
        total_fetched = 0
        total_saved = 0

        current = start_date
        while current < end_date:
            chunk_end = min(current + timedelta(days=chunk_days), end_date)

            # Check if chunk already completed
            if await self._is_chunk_completed(sync_state.id, current, chunk_end):
                logger.info(f"Skipping completed chunk: {current} to {chunk_end}")
                current = chunk_end
                continue

            # Create run record
            sync_run = SyncRun(
                sync_state_id=sync_state.id,
                run_type="historical_chunk",
                start_date=datetime.combine(current, datetime.min.time()),
                end_date=datetime.combine(chunk_end, datetime.min.time()),
                status="running",
                started_at=datetime.utcnow(),
            )
            self.db.add(sync_run)
            await self.db.flush()

            try:
                # Fetch chunk
                last_mod_start = current.strftime("%Y-%m-%dT00:00:00.000")
                last_mod_end = chunk_end.strftime("%Y-%m-%dT23:59:59.999")

                vulnerabilities = []
                async for page in self.fetcher.iter_pages(
                        last_mod_start=last_mod_start,
                        last_mod_end=last_mod_end,
                ):
                    vulnerabilities.extend(page.vulnerabilities or [])

                # Transform and import
                records = [self.fetcher.transform(v) for v in vulnerabilities]
                if records:
                    saved = await self.importer.process_enriched_records(records)
                    await self.db.commit()
                    total_saved += saved

                total_fetched += len(vulnerabilities)

                # Mark chunk complete
                sync_run.status = "completed"
                sync_run.records_processed = len(vulnerabilities)
                sync_run.records_saved = len(records) if records else 0
                sync_run.completed_at = datetime.utcnow()
                await self.db.commit()

                logger.info(f"Chunk {current} to {chunk_end}: {len(vulnerabilities)} fetched")

            except Exception as e:
                sync_run.status = "failed"
                sync_run.error_message = str(e)
                sync_run.completed_at = datetime.utcnow()
                await self.db.commit()
                raise

            current = chunk_end

        # Update state
        sync_state.last_sync_date = datetime.utcnow()
        sync_state.status = "completed"
        await self.db.commit()

        return {"total_fetched": total_fetched, "total_saved": total_saved}

    async def _get_or_create_sync_state(self, sync_type: str) -> SyncState:
        from sqlalchemy import select
        result = await self.db.execute(
            select(SyncState).where(SyncState.sync_type == sync_type)
        )
        state = result.scalar_one_or_none()
        if not state:
            state = SyncState(sync_type=sync_type, status="idle")
            self.db.add(state)
            await self.db.flush()
        return state

    async def _is_chunk_completed(
            self, state_id: int, start: date, end: date
    ) -> bool:
        from sqlalchemy import select
        result = await self.db.execute(
            select(SyncRun).where(
                SyncRun.sync_state_id == state_id,
                SyncRun.start_date == datetime.combine(start, datetime.min.time()),
                SyncRun.end_date == datetime.combine(end, datetime.min.time()),
                SyncRun.status == "completed",
                )
        )
        return result.scalar_one_or_none() is not None