"""Route handlers and dashboard for background CVE synchronization."""

import asyncio
import time
import logging
from datetime import datetime
from typing import Optional
from aiohttp import web

from src.config.database import SessionLocal
from src.fetchers.pipelines import run_enrichment_pipeline
from src.services.Database.storage import DatabaseStorage

logger = logging.getLogger(__name__)


# Beautiful dark mode dashboard HTML
HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnRadar — Sync Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(22, 31, 48, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: hsl(252, 85%, 68%);
            --primary-glow: rgba(138, 92, 246, 0.4);
            --text-color: #e2e8f0;
            --text-muted: #94a3b8;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Outfit', sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 2.5rem 1.5rem;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(139, 92, 246, 0.05) 0%, transparent 40%);
        }

        .container {
            width: 100%;
            max-width: 800px;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        header {
            text-align: center;
            margin-bottom: 1rem;
        }

        header h1 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.5rem;
            font-weight: 700;
            letter-spacing: -1px;
            background: linear-gradient(135deg, #a78bfa 0%, #818cf8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        header p {
            color: var(--text-muted);
            font-size: 1.1rem;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
        }

        .card-title {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.3rem;
            margin-bottom: 1.5rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }

        @media (max-width: 600px) {
            .form-grid {
                grid-template-columns: 1fr;
            }
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .input-group label {
            font-size: 0.9rem;
            color: var(--text-muted);
            font-weight: 600;
        }

        .input-group input {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 0.8rem 1rem;
            color: var(--text-color);
            font-family: inherit;
            font-size: 1rem;
            transition: all 0.2s ease;
        }

        .input-group input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-glow);
        }

        button.btn-trigger {
            width: 100%;
            background: linear-gradient(135deg, var(--primary) 0%, #6366f1 100%);
            border: none;
            border-radius: 10px;
            padding: 1rem;
            color: white;
            font-family: inherit;
            font-weight: 600;
            font-size: 1.1rem;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
        }

        button.btn-trigger:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.45);
        }

        button.btn-trigger:active {
            transform: translateY(0);
        }

        .status-container {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .status-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .badge {
            padding: 0.4rem 1rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-idle { background: #334155; color: #cbd5e1; }
        .badge-syncing { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
        .badge-completed { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
        .badge-failed { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }

        .progress-container {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .progress-bar {
            width: 100%;
            height: 12px;
            background: rgba(15, 23, 42, 0.8);
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }

        .progress-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--primary) 0%, #3b82f6 100%);
            border-radius: 6px;
            transition: width 0.3s ease;
        }

        .progress-text {
            display: flex;
            justify-content: space-between;
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
            text-align: center;
        }

        .info-card {
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1rem;
        }

        .info-value {
            font-size: 1.5rem;
            font-weight: 700;
            margin-top: 0.25rem;
        }

        .info-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .results-container {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            max-height: 300px;
            overflow-y: auto;
            padding-right: 0.5rem;
        }

        .results-container::-webkit-scrollbar {
            width: 6px;
        }

        .results-container::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.1);
            border-radius: 3px;
        }

        .results-container::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.1);
            border-radius: 3px;
        }

        .cve-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 0.8rem 1.2rem;
            transition: border-color 0.2s ease;
        }

        .cve-row:hover {
            border-color: rgba(255, 255, 255, 0.15);
        }

        .cve-id {
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 700;
            color: #cbd5e1;
        }

        .sev-tag {
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }

        .sev-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .sev-HIGH { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
        .sev-MEDIUM { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
        .sev-LOW { background: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid #64748b; }
        .sev-UNKNOWN { background: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid #475569; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>VulnRadar</h1>
            <p>CVE Enrichment Pipeline Control Room</p>
        </header>

        <!-- Configuration Card -->
        <div class="card">
            <div class="card-title">⚙️ Sync Configuration</div>
            <div class="form-grid">
                <div class="input-group">
                    <label for="startDate">Start Date</label>
                    <input type="date" id="startDate" value="2026-06-01">
                </div>
                <div class="input-group">
                    <label for="endDate">End Date</label>
                    <input type="date" id="endDate">
                </div>
            </div>
            <button class="btn-trigger" id="btnTrigger" onclick="startSync()">Trigger Synchronization</button>
        </div>

        <!-- Progress Card -->
        <div class="card" id="progressCard" style="display: none;">
            <div class="status-container">
                <div class="status-header">
                    <div style="display: flex; flex-direction: column; gap: 0.25rem;">
                        <span id="jobIdLabel" style="font-size: 0.8rem; color: var(--text-muted); font-family: monospace;">JOB: -</span>
                        <h2 style="font-family: 'Space Grotesk', sans-serif; font-size: 1.2rem;">Pipeline Status</h2>
                    </div>
                    <span class="badge badge-idle" id="statusBadge">Idle</span>
                </div>

                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <div class="progress-text">
                        <span id="stageLabel">Ready</span>
                        <span id="percentLabel">0%</span>
                    </div>
                </div>

                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Processed</div>
                        <div class="info-value" id="valProcessed">0</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Total</div>
                        <div class="info-value" id="valTotal">0</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Saved Rows</div>
                        <div class="info-value" id="valSaved">0</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Results Card -->
        <div class="card" id="resultsCard" style="display: none;">
            <div class="card-title">📋 Sync Results</div>
            <div class="results-container" id="resultsList">
                <!-- CVE rows injected here -->
            </div>
        </div>
    </div>

    <script>
        // Set default end date to today
        document.getElementById('endDate').value = new Date().toISOString().split('T')[0];

        let activeJobId = null;
        let pollInterval = null;

        async function startSync() {
            const startDate = document.getElementById('startDate').value;
            const endDate = document.getElementById('endDate').value;

            if (!startDate) {
                alert('Please select a start date.');
                return;
            }

            const btn = document.getElementById('btnTrigger');
            btn.disabled = true;
            btn.innerText = 'Initializing Pipeline...';

            try {
                const response = await fetch('/api/v1/pipeline/sync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ start_date: startDate, end_date: endDate })
                });

                if (!response.ok) {
                    const err = await response.json();
                    alert(`Sync failed to start: ${err.error || response.statusText}`);
                    btn.disabled = false;
                    btn.innerText = 'Trigger Synchronization';
                    return;
                }

                const data = await response.json();
                activeJobId = data.job_id;

                // Show panels
                document.getElementById('progressCard').style.display = 'block';
                document.getElementById('jobIdLabel').innerText = `JOB: ${activeJobId}`;
                document.getElementById('resultsCard').style.display = 'none';
                document.getElementById('resultsList').innerHTML = '';

                // Reset labels
                updateUIState('syncing', 'Starting', 0, 0, 0, 0);

                // Start polling
                if (pollInterval) clearInterval(pollInterval);
                pollInterval = setInterval(pollJobStatus, 1000);

            } catch (e) {
                alert(`Error starting sync: ${e}`);
                btn.disabled = false;
                btn.innerText = 'Trigger Synchronization';
            }
        }

        async function pollJobStatus() {
            if (!activeJobId) return;

            try {
                const response = await fetch(`/api/v1/pipeline/status/${activeJobId}`);
                if (!response.ok) return;

                const job = await response.json();
                
                const status = job.status;
                const stage = job.stage || 'syncing';
                const total = job.total_records || 0;
                const processed = job.processed_records || 0;
                const saved = job.records_processed || 0;
                const pct = job.progress_percentage || 0;

                updateUIState(status, stage, pct, processed, total, saved);

                if (status === 'completed') {
                    clearInterval(pollInterval);
                    document.getElementById('btnTrigger').disabled = false;
                    document.getElementById('btnTrigger').innerText = 'Trigger Synchronization';
                    
                    // Display results
                    if (job.results && job.results.length > 0) {
                        displayResults(job.results);
                    }
                } else if (status === 'failed') {
                    clearInterval(pollInterval);
                    document.getElementById('btnTrigger').disabled = false;
                    document.getElementById('btnTrigger').innerText = 'Trigger Synchronization';
                    alert(`Synchronization failed: ${job.error}`);
                }

            } catch (e) {
                console.error('Polling error:', e);
            }
        }

        function updateUIState(status, stage, pct, processed, total, saved) {
            // Update badge class
            const badge = document.getElementById('statusBadge');
            badge.className = `badge badge-${status}`;
            badge.innerText = status;

            // Update progress bar
            document.getElementById('progressFill').style.width = `${pct}%`;
            document.getElementById('percentLabel').innerText = `${pct}%`;

            // Update stage label text
            let stageText = 'Processing...';
            if (stage === 'enriching_epss') stageText = '⚡ Enriching EPSS scores...';
            else if (stage === 'enriching_nvd') stageText = '🔍 Loading NVD attributes...';
            else if (stage === 'enriching_exploits') stageText = '⚔️ Searching exploit intel...';
            else if (stage === 'saving') stageText = '💾 Saving database rows...';
            else if (status === 'completed') stageText = '✅ Completed';
            else if (status === 'failed') stageText = '❌ Sync Failed';

            document.getElementById('stageLabel').innerText = stageText;

            // Update stats cards
            document.getElementById('valProcessed').innerText = processed;
            document.getElementById('valTotal').innerText = total;
            document.getElementById('valSaved').innerText = saved;
        }

        function displayResults(results) {
            const list = document.getElementById('resultsList');
            list.innerHTML = '';
            
            results.forEach(item => {
                const row = document.createElement('div');
                row.className = 'cve-row';
                
                const cveSpan = document.createElement('span');
                cveSpan.className = 'cve-id';
                cveSpan.innerText = item.cve_id;

                const sevSpan = document.createElement('span');
                const sev = item.severity || 'UNKNOWN';
                sevSpan.className = `sev-tag sev-${sev}`;
                sevSpan.innerText = sev;

                row.appendChild(cveSpan);
                row.appendChild(sevSpan);
                list.appendChild(row);
            });

            document.getElementById('resultsCard').style.display = 'block';
        }
    </script>
</body>
</html>
"""


async def get_dashboard_handler(request: web.Request) -> web.Response:
    """Serve the HTML dashboard for synchronization control and progress monitoring."""
    return web.Response(text=HTML_DASHBOARD, content_type="text/html")


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
        # 1. Fetch and enrich records using manual date filters and progress reporting
        records = await run_enrichment_pipeline(
            limit=None,  # Fetch all matching KEVs
            include_epss=True,
            include_nvd=True,
            include_exploits=True,
            incremental=False,  # Bypass incremental latest-DB logic
            start_date=start_date,
            end_date=end_date,
            on_progress=on_progress,
        )

        app["sync_jobs"][job_id]["stage"] = "saving"

        # 2. Persist to DB
        import src.config.database as db_config
        db_config.init_db()
        db = db_config.SessionLocal()
        try:
            storage = DatabaseStorage(db)
            saved_count = storage.save_enriched_cves(records)
        finally:
            db.close()

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
