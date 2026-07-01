import asyncio
import logging
import os
import aiohttp_jinja2
import jinja2
from aiohttp import web
from aiohttp_middlewares import cors_middleware

from src.api.router import setup_routes
from src.api.middleware.rate_limiter import rate_limiter_middleware
from src.api.middleware.auth import auth_middleware  # ADD THIS IMPORT
from src.jobs.scheduler import SchedulerManager
import src.services.logger as logger

_log = logger.Logger("api_app", level="INFO", log_file="logs/api_app.log")


async def scheduler_ctx(app: web.Application):
    """Lifecycle context manager to start/stop the scheduler with the server."""
    _log.info("Initializing APScheduler background jobs")
    manager = SchedulerManager()
    manager.register_jobs()
    manager.start()
    asyncio.create_task(manager.run_sync_job())

    app["scheduler"] = manager

    yield

    _log.info("Shutting down APScheduler background jobs")
    manager.shutdown()


def create_app() -> web.Application:
    _log.info("Creating aiohttp web application")

    # 1. Initialize app with CORS + Auth + Rate Limiting middleware
    app = web.Application(
        middlewares=[
            cors_middleware(
                origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                allow_headers=["Content-Type", "Authorization"],
                allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            ),
            auth_middleware,  # REMOVE () — it's a decorator, not a function call
            rate_limiter_middleware(requests_per_minute=60)
        ]
    )

    # Initialize aiohttp_jinja2 template loader
    aiohttp_jinja2.setup(
        app,
        loader=jinja2.FileSystemLoader("src/templates")
    )

    # 2. Register central router endpoints
    setup_routes(app)
    _log.info("Registered all API route endpoints")

    # 3. Register background scheduler lifecycle hooks
    app.cleanup_ctx.append(scheduler_ctx)

    log_level = os.getenv("LOG_LEVEL", "INFO")
    log_format = os.getenv("LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    _log.debug(f"LOG_LEVEL: {log_level}")
    _log.debug(f"LOG_FORMAT: {log_format}")
    logging.basicConfig(level=log_level, format=log_format)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    _log.debug("Suppressed noisy logs from aiohttp, urllib3")
    _log.info("Application created successfully")
    return app


if __name__ == '__main__':
    host = os.getenv("APP_HOST", "127.0.0.1")
    port = int(os.getenv("APP_PORT", "8000"))
    _log.info(f"Starting aiohttp server on {host}:{port}")
    web.run_app(create_app(), host=host, port=port)