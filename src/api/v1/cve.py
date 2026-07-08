from aiohttp import web
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from src.api.middleware.auth import require_auth
from src.config.database import db_session_ro
from src.models.cve import Cve
from src.models.cve_details import CveDescription, CveTag
from src.models.cvss import CvssMetricV2, CvssDataV2
from src.models.cvss_models import CvssMetricV31, CvssDataV31, CvssMetricV40, CvssDataV40
from src.models.configuration import CveConfiguration, CveNode, CpeMatch
from src.models.reference import CveReference
from src.models.weakness import CveWeakness, CveWeaknessDescription
from src.models.epss import Epss
from src.models.exploit import ExploitReference
from src.models.osv import OsvRecord, OsvReference
from src.models.github_advisory import GithubAdvisory, GithubAdvisoryReference
from src.models.vendor_advisory import VendorAdvisory

routes = web.RouteTableDef()


# ── LIST ────────────────────────────────────────────────────────────────────

@routes.get("/api/v1/cve/list")
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


# ── DETAIL ──────────────────────────────────────────────────────────────────

@routes.get("/api/v1/cve/{cve_id}")
@require_auth
async def get_cve(request):
    """Return one CVE with all nested relations."""
    cve_id = request.match_info["cve_id"]

    with db_session_ro() as db:
        result = db.execute(
            select(Cve)
            .where(Cve.cve_id == cve_id)
            .options(
                joinedload(Cve.tags),
                joinedload(Cve.descriptions),
                joinedload(Cve.cvss_v2_metrics).joinedload(CvssMetricV2.cvss_data),
                joinedload(Cve.cvss_v31_metrics).joinedload(CvssMetricV31.cvss_data),
                joinedload(Cve.cvss_v40_metrics).joinedload(CvssMetricV40.cvss_data),
                joinedload(Cve.weaknesses).joinedload(CveWeakness.descriptions),
                joinedload(Cve.configurations)
                .joinedload(CveConfiguration.nodes)
                .joinedload(CveNode.cpe_matches),
                joinedload(Cve.references),
                joinedload(Cve.epss),
                joinedload(Cve.exploit_references),
                joinedload(Cve.osv_records).joinedload(OsvRecord.references),
                joinedload(Cve.github_advisories).joinedload(GithubAdvisory.references),
                joinedload(Cve.vendor_advisories),
                )
        )
        cve = result.unique().scalar_one_or_none()
        if not cve:
            return web.json_response({
                "cve": None,
                "count": 0,
                "message": "CVE not found.",
            }, status=404)
        data = cve.to_dict()
        data["tags"] = [t.value for t in cve.tags]
        data["descriptions"] = [{"lang": d.lang, "value": d.value} for d in cve.descriptions]
        data["cvss_v2_metrics"] = [_cvss_v2_to_dict(m) for m in cve.cvss_v2_metrics]
        data["cvss_v31_metrics"] = [_cvss_v31_to_dict(m) for m in cve.cvss_v31_metrics]
        data["cvss_v40_metrics"] = [_cvss_v40_to_dict(m) for m in cve.cvss_v40_metrics]
        data["weaknesses"] = [_weakness_to_dict(w) for w in cve.weaknesses]
        data["configurations"] = [_config_to_dict(c) for c in cve.configurations]
        data["references"] = [{"url": r.url, "source": r.source} for r in cve.references]
        data["epss"] = [e.to_dict() for e in cve.epss]
        data["exploit_references"] = [e.to_dict() for e in cve.exploit_references]
        data["osv_records"] = [r.to_dict() for r in cve.osv_records]
        data["github_advisories"] = [a.to_dict() for a in cve.github_advisories]
        data["vendor_advisories"] = [a.to_dict() for a in cve.vendor_advisories]
    return web.json_response({
        "cve": data,
        "count": 1,
    })


cve_routes = routes