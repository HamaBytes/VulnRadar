from datetime import datetime
from decimal import Decimal
from typing import Optional

from src.schemas.base import BaseSchema


class ProjectItemSchema(BaseSchema):
    id: int
    project_id: int
    asset_name: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    cve_id: str
    cve_db_id: Optional[int] = None
    criticality: Optional[str] = None
    status: str = "analysis"
    risk_score: Optional[Decimal] = None
    risk_reasons: Optional[dict] = None
    ai_summary: Optional[str] = None
    created_at: Optional[datetime] = None


class ProjectSchema(BaseSchema):
    id: int
    user_id: int
    name: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    items: list[ProjectItemSchema] = []