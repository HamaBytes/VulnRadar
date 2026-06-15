"""Central route registration for VulnRadar API."""

from aiohttp import web
from src.api.v1.health import health_endpoint, get_landing_page_handler
from src.api.v1.pipeline import start_sync_handler, get_status_handler, get_dashboard_handler


def setup_routes(app: web.Application) -> None:
    """Register all versioned endpoints on the application router."""
    # Initialize background jobs tracking dictionary
    app["sync_jobs"] = {}

    # Root landing gateway status page
    app.router.add_get("/", get_landing_page_handler)

    # Health check routes
    app.router.add_get("/api/v1/health", health_endpoint)
    app.router.add_get("/api/health", health_endpoint)

    # Sync pipeline routes
    app.router.add_post("/api/v1/pipeline/sync", start_sync_handler)
    app.router.add_get("/api/v1/pipeline/sync", get_dashboard_handler)
    app.router.add_get("/api/v1/pipeline/status/{job_id}", get_status_handler)
