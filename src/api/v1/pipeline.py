"""Route handlers and dashboard for background CVE synchronization."""
import asyncio
import time
import logging
from datetime import datetime
from typing import Optional
import aiohttp_jinja2
from aiohttp import web

from src.config.database import db_session, init_db
from src.fetchers.pipelines import run_enrichment_pipeline
from src.services.Database.storage import DatabaseStorage

logger = logging.getLogger(__name__)


@aiohttp_jinja2.template("sync_dashboard.html")
async def get_dashboard_handler(request: web.Request) -> dict:
    """Serve the HTML dashboard for synchronization control and progress monitoring."""
    return {}


async def _run_background_sync(
    app: web.Application,
    job_id: str,
    start_date: Optional[datetime.date],
    end_date: Optional[datetime.date]
) -> None:
    """Run the synchronization pipeline in the background and record progress."""
    logger.info(f"Background sync job {job_id} started")
    
    # Progress callback passed to the sync pipelines
    def on_progress(current: int, total: int, stage: str):
        progress_pct = int((current / total) * 100) if total > 0 else 0
        app["sync_jobs"][job_id].update({
            "stage": stage,
            "total_records": total,
            "processed_records": current,
            "progress_percentage": progress_pct
        })

    try:
        # 1. Fetch and enrich records using manual or incremental sync
        incremental_sync = not (start_date or end_date)
        records = await run_enrichment_pipeline(
            limit=None,  # Fetch all matching KEVs
            include_epss=True,
            include_nvd=True,
            include_exploits=True,
            incremental=incremental_sync,
            start_date=start_date,
            end_date=end_date,
            on_progress=on_progress,
        )

        app["sync_jobs"][job_id]["stage"] = "saving"

        # 2. Persist to DB
        init_db()
        with db_session() as db:
            storage = DatabaseStorage(db)
            saved_count = storage.save_enriched_cves(records)

        # Format results summary to return list of saved CVE IDs and severity
        results_summary = [
            {
                "cve_id": r.get("cveID"),
                "severity": r.get("nvd_base_severity") or "UNKNOWN"
            }
            for r in records
        ]

        # 3. Mark job status as completed
        app["sync_jobs"][job_id].update({
            "status": "completed",
            "completed_at": datetime.utcnow().isoformat(),
            "records_processed": saved_count,
            "progress_percentage": 100,
            "results": results_summary
        })
        logger.info(f"Background sync job {job_id} finished. Saved {saved_count} records.")

    except Exception as e:
        logger.error(f"Background sync job {job_id} failed: {e}", exc_info=True)
        app["sync_jobs"][job_id].update({
            "status": "failed",
            "completed_at": datetime.utcnow().isoformat(),
            "error": str(e)
        })


async def start_sync_handler(request: web.Request) -> web.Response:
    """Start an incremental or manual date range sync job in the background."""
    try:
        data = await request.json()
    except Exception:
        data = {}

    start_date_str = data.get("start_date")
    end_date_str = data.get("end_date")

    start_date = None
    end_date = None

    # Parse and validate dates
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        except ValueError:
            return web.json_response(
                {"error": "Invalid start_date format. Use YYYY-MM-DD."},
                status=400
            )

    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
        except ValueError:
            return web.json_response(
                {"error": "Invalid end_date format. Use YYYY-MM-DD."},
                status=400
            )

    # Initialize job tracking state
    job_id = f"sync_{int(time.time())}"
    request.app["sync_jobs"][job_id] = {
        "status": "syncing",
        "stage": "starting",
        "progress_percentage": 0,
        "total_records": 0,
        "processed_records": 0,
        "start_date": start_date_str,
        "end_date": end_date_str,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "records_processed": 0,
        "error": None,
        "results": []
    }

    # Launch task in the asyncio event loop background
    asyncio.create_task(
        _run_background_sync(request.app, job_id, start_date, end_date)
    )

    return web.json_response({
        "status": "syncing",
        "job_id": job_id,
        "message": "Synchronization task started in the background."
    }, status=202)


async def get_status_handler(request: web.Request) -> web.Response:
    """Retrieve execution details, progress, and status of a sync job."""
    job_id = request.match_info.get("job_id")
    if not job_id:
        return web.json_response({"error": "Missing job_id parameter"}, status=400)

    job_state = request.app["sync_jobs"].get(job_id)
    if not job_state:
        return web.json_response({"error": f"Sync job {job_id} not found"}, status=404)

    return web.json_response(job_state)
