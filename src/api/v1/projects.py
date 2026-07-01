from aiohttp import web
from sqlalchemy import select, func ,update , delete
from sqlalchemy.orm import joinedload

from src.config.database import db_session, db_session_ro
from src.models.projects import Project, ProjectItem
from src.api.middleware.auth import require_auth

routes = web.RouteTableDef()


@routes.post("/api/v1/projects/add")
@require_auth
async def create_project(request):
    if "user" not in request:
        return web.json_response({"error": "Authentication required"}, status=401)

    user = request["user"]
    data = await request.json()

    name = data.get("name", "").strip()
    description = data.get("description", "").strip() or None

    if not name:
        return web.json_response({"error": "Project name is required"}, status=400)

    with db_session() as db:
        project = Project(
            user_id=user["id"],
            name=name,
            description=description
        )
        db.add(project)
        db.commit()  # Explicit commit needed since we may need refresh after
        db.refresh(project)

        return web.json_response({
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "created_at": project.created_at.isoformat(),
            "item_count": 0
        }, status=201)


@routes.get("/api/v1/projects")
@require_auth
async def list_projects(request):
    user = request["user"]

    with db_session_ro() as db:
        result = db.execute(
            select(Project, func.count(ProjectItem.id).label("item_count"))
            .outerjoin(ProjectItem)
            .where(Project.user_id == user["id"])
            .group_by(Project.id)
            .order_by(Project.created_at.desc())
        )

        projects = []
        for project, item_count in result:
            projects.append({
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "created_at": project.created_at.isoformat(),
                "item_count": item_count
            })

        return web.json_response({"projects": projects})


@routes.get("/api/v1/projects/{id}")
@require_auth
async def get_project(request):
    user = request["user"]
    project_id = int(request.match_info["id"])

    with db_session_ro() as db:
        result = db.execute(
            select(Project)
            .where(Project.id == project_id, Project.user_id == user["id"])
        )
        project = result.scalar_one_or_none()

        if not project:
            return web.json_response({"error": "Project not found"}, status=404)

        # Count items
        item_count = db.execute(
            select(func.count(ProjectItem.id))
            .where(ProjectItem.project_id == project_id)
        ).scalar()

        return web.json_response({
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "created_at": project.created_at.isoformat(),
            "item_count": item_count
        })


def _serialize_project_item(item):
    return {
        "id": item.id,
        "project_id": item.project_id,
        "asset_name": item.asset_name,
        "ip": item.ip,
        "hostname": item.hostname,
        "cve_id": item.cve_id,
        "cve_db_id": item.cve_db_id,
        "criticality": item.criticality,
        "status": item.status,
        "risk_score": float(item.risk_score) if item.risk_score is not None else None,
        "risk_reasons": item.risk_reasons,
        "ai_summary": item.ai_summary,
        "created_at": item.created_at.isoformat(),
    }


def _get_user_project(db, project_id, user_id):
    return db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == user_id)
    ).scalar_one_or_none()


@routes.post("/api/v1/projects/{id}/items")
@require_auth
async def add_project_item(request):
    user = request["user"]
    project_id = int(request.match_info["id"])
    data = await request.json()

    cve_id = data.get("cve_id", "").strip()
    asset_name = data.get("asset_name", "").strip()
    ip = data.get("ip")
    hostname = data.get("hostname")
    cve_db_id = data.get("cve_db_id")
    criticality = data.get("criticality")
    status = data.get("status", "analysis")
    risk_score = data.get("risk_score")
    risk_reasons = data.get("risk_reasons")
    ai_summary = data.get("ai_summary")

    if not cve_id:
        return web.json_response({"error": "cve_id is required"}, status=400)
    if not asset_name:
        return web.json_response({"error": "asset_name is required"}, status=400)

    with db_session() as db:
        project = _get_user_project(db, project_id, user["id"])
        if not project:
            return web.json_response({"error": "Project not found"}, status=404)

        item = ProjectItem(
            project_id=project_id,
            asset_name=asset_name,
            ip=ip,
            hostname=hostname,
            cve_id=cve_id,
            cve_db_id=int(cve_db_id) if cve_db_id is not None else None,
            criticality=criticality,
            status=status,
            risk_score=float(risk_score) if risk_score is not None else None,
            risk_reasons=risk_reasons,
            ai_summary=ai_summary,
        )
        db.add(item)
        db.commit()
        db.refresh(item)

        return web.json_response(_serialize_project_item(item), status=201)


@routes.get("/api/v1/projects/{id}/items")
@require_auth
async def list_project_items(request):
    user = request["user"]
    project_id = int(request.match_info["id"])

    with db_session_ro() as db:
        project = _get_user_project(db, project_id, user["id"])
        if not project:
            return web.json_response({"error": "Project not found"}, status=404)

        result = db.execute(
            select(ProjectItem)
            .where(ProjectItem.project_id == project_id)
            .order_by(ProjectItem.created_at.desc())
        )
        items = [
            _serialize_project_item(item)
            for item in result.scalars().all()
        ]

        return web.json_response({"items": items})


@routes.delete("/api/v1/projects/{id}/items/{cve_id}")
@require_auth
async def delete_project_item(request):
    user = request["user"]
    project_id = int(request.match_info["id"])
    cve_id = request.match_info["cve_id"]

    with db_session_ro() as db:
        project = _get_user_project(db, project_id, user["id"])
        if not project:
            return web.json_response({"error": "Project not found"}, status=404)

    with db_session() as db:
        result = db.execute(
            delete(ProjectItem)
            .where(ProjectItem.project_id == project_id, ProjectItem.cve_id == cve_id)
        )

        if result.rowcount == 0:
            return web.json_response({"error": "Project item not found"}, status=404)

        return web.json_response({"status": "deleted"}, status=200)


@routes.patch("/api/v1/projects/{id}/items/{cve_id}")
@require_auth
async def update_project_item(request):
    user = request["user"]
    project_id = int(request.match_info["id"])
    cve_id = request.match_info["cve_id"]
    data = await request.json()

    update_values = {}
    if "asset_name" in data:
        asset_name = data.get("asset_name", "").strip()
        if not asset_name:
            return web.json_response({"error": "asset_name cannot be empty"}, status=400)
        update_values["asset_name"] = asset_name
    if "ip" in data:
        update_values["ip"] = data.get("ip")
    if "hostname" in data:
        update_values["hostname"] = data.get("hostname")
    if "criticality" in data:
        update_values["criticality"] = data.get("criticality")
    if "status" in data:
        update_values["status"] = data.get("status")
    if "risk_score" in data:
        update_values["risk_score"] = float(data.get("risk_score")) if data.get("risk_score") is not None else None
    if "risk_reasons" in data:
        update_values["risk_reasons"] = data.get("risk_reasons")
    if "ai_summary" in data:
        update_values["ai_summary"] = data.get("ai_summary")

    if not update_values:
        return web.json_response({"error": "No valid fields to update"}, status=400)

    with db_session_ro() as db:
        project = _get_user_project(db, project_id, user["id"])
        if not project:
            return web.json_response({"error": "Project not found"}, status=404)

    with db_session() as db:
        result = db.execute(
            update(ProjectItem)
            .where(ProjectItem.project_id == project_id, ProjectItem.cve_id == cve_id)
            .values(**update_values)
        )

        if result.rowcount == 0:
            return web.json_response({"error": "Project item not found"}, status=404)

        updated_item = db.execute(
            select(ProjectItem)
            .where(ProjectItem.project_id == project_id, ProjectItem.cve_id == cve_id)
        ).scalar_one()

        return web.json_response(_serialize_project_item(updated_item))


@routes.patch("/api/v1/projects/{id}")
@require_auth
async def update_project(request):
    user = request["user"]
    project_id = int(request.match_info["id"])
    data = await request.json()
    name = data.get("name", "").strip()
    description = data.get("description", "").strip() or None

    with db_session() as db:
        result = db.execute(
            update(Project)
            .where(Project.id == project_id, Project.user_id == user["id"])
            .values(name=name, description=description)
            .returning(Project)
        )
        updated_project = result.scalar_one_or_none()

        if not updated_project:
            return web.json_response({"error": "Project not found"}, status=404)

        db.commit()
        db.refresh(updated_project)

        return web.json_response({
            "id": updated_project.id,
            "name": updated_project.name,
            "description": updated_project.description
        })

@routes.delete("/api/v1/projects/{id}")
@require_auth
async def delete_project(request):
    user = request["user"]
    project_id = int(request.match_info["id"])

    with db_session() as db:
        result = db.execute(
            delete(Project).where(Project.user_id == user["id"], Project.id == project_id)
        )

        if result.rowcount == 0:
            return web.json_response({"error": "Project not found"}, status=404)

        db.commit()
        return web.json_response({"status": "deleted"}, status=200)





project_routes = routes