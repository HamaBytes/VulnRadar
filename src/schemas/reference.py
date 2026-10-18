from typing import Optional

from src.schemas.base import BaseSchema


class CveReferenceSchema(BaseSchema):
    id: int
    cve_db_id: int
    url: str
    source: Optional[str] = None