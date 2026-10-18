from datetime import datetime
from typing import Optional

from src.schemas.base import BaseSchema


class GithubAdvisoryReferenceSchema(BaseSchema):
    id: int
    github_advisory_id: int
    url: str
    source: Optional[str] = None


class GithubAdvisorySchema(BaseSchema):
    id: int
    cve_db_id: int
    summary: Optional[str] = None
    severity: Optional[str] = None
    package_name: Optional[str] = None
    created_at: Optional[datetime] = None
    references: list[GithubAdvisoryReferenceSchema] = []