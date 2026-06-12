"""Route handlers for the API layer."""

from __future__ import annotations

from aiohttp import web

from src.config.config import Config
from src.config.database import init_db


def health_check() -> dict[str, object]:
    status: dict[str, object] = {
        "status": "ok",
        "database": {"connected": False},
        "nvd_api_key": {"present": bool(Config.NVD_API_KEY)},
    }

    try:
        engine = init_db()
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")

        status["database"] = {"connected": True}
    except Exception as error:
        status["status"] = "degraded"
        status["database"] = {"connected": False, "error": str(error)}

    if not Config.NVD_API_KEY:
        status["status"] = "degraded"

    return status


async def health_endpoint(request: web.Request) -> web.Response:
    return web.json_response(health_check())
