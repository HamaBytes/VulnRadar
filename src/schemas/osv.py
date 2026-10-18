from datetime import datetime
from typing import Optional

from src.schemas.base import BaseSchema


class OsvReferenceSchema(BaseSchema):
    id: int
    osv_record_id: int
    url: str
    source_id: Optional[str] = None
    title: Optional[str] = None


class OsvRecordSchema(BaseSchema):
    id: int
    cve_db_id: int
    osv_id: Optional[str] = None
    summary: Optional[str] = None
    severities: list = []
    created_at: Optional[datetime] = None
    references: list[OsvReferenceSchema] = []