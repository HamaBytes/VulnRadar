from aiohttp import web
from sqlalchemy import select, func
from sqlalchemy.orm import joinedload
from src.config.database import SessionLocal
from src.models.projects import Project, ProjectItem
from src.api.middleware.auth import require_auth

routes = web.RouteTableDef()


@routes.post("/api/v1/projects")
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

    db = SessionLocal()
    try:
        project = Project(
            user_id=user["id"],
            name=name,
            description=description
        )
        db.add(project)
        db.commit()
        db.refresh(project)

        return web.json_response({
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "created_at": project.created_at.isoformat(),
            "item_count": 0
        }, status=201)
    finally:
        db.close()


@routes.get("/api/v1/projects")
@require_auth
async def list_projects(request):
    user = request["user"]

    db = SessionLocal()
    try:
        # Get projects with item count
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
    finally:
        db.close()


@routes.get("/api/v1/projects/{id}")
@require_auth
async def get_project(request):
    user = request["user"]
    project_id = int(request.match_info["id"])

    db = SessionLocal()
    try:
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
    finally:
        db.close()


project_routes = routes