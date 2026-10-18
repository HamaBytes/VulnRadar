from datetime import datetime
from typing import Optional

from src.schemas.base import BaseSchema


class VendorAdvisorySchema(BaseSchema):
    id: int
    cve_db_id: int
    vendor: Optional[str] = None
    is_available: bool = False
    sources: list = []
    details: Optional[str] = None
    created_at: Optional[datetime] = None