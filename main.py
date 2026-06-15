import logging
import os
from aiohttp import web

from src.api.router import setup_routes
from src.api.middleware.rate_limiter import rate_limiter_middleware
from src.jobs.scheduler import SchedulerManager
import src.services.logger as logger

_log = logger.Logger("api_app", level="INFO", log_file="logs/api_app.log")


async def scheduler_ctx(app: web.Application):
    """Lifecycle context manager to start/stop the scheduler with the server."""
    _log.info("Initializing APScheduler background jobs")
    manager = SchedulerManager()
    manager.register_jobs()
    manager.start()
    
    app["scheduler"] = manager
    
    yield
    
    _log.info("Shutting down APScheduler background jobs")
    manager.shutdown()


def create_app() -> web.Application:
    _log.info("Creating aiohttp web application")
    
    # 1. Initialize app with Rate Limiting middleware (60 req/min limit)
    app = web.Application(
        middlewares=[rate_limiter_middleware(requests_per_minute=60)]
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