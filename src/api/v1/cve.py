from aiohttp import web
from sqlalchemy import select

from src.api.middleware.auth import require_auth
from src.config.database import db_session_ro
import src.models
routes = web.RouteTableDef()
@routes.get("/api/v1/cve/list")
@routes.get("/api/v1/cves")
@require_auth
async def cve_list(request):
    """Return all CVEs stored in the database."""
    with db_session_ro() as db:
        result = db.execute(
            select(Cve)
            .order_by(Cve.created_at.desc())
        )
        cves = [cve.to_dict() for cve in result.scalars().all()]

    return web.json_response({
        "cves": cves,
        "count": len(cves),
    })

@routes.get("/api/v1/cve/{cve_id}")
async def get_cve(request):
    """Return one CVE."""
    with db_session_ro() as db:
        result = db.execute(
            select(Cve , cpe_marches , cve_configuera, cve_description , cve_node , cve_refrenceces , cve_)
            .where(Cve.cve_id == request.match_info["cve_id"])
            .order_by(Cve.created_at.desc())
            .limit(1)

        )
        cve = result.scalar_one_or_none()
        if not cve:
            return web.json_response({
                "cve": cve.to_dict(),
                "count": 0,
                "message": "Cve not found.",

            })
