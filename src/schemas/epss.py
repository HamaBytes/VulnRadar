from decimal import Decimal
from typing import Optional

from src.schemas.base import BaseSchema


class EpssSchema(BaseSchema):
    id: int
    cve_db_id: int
    epss_score: Optional[Decimal] = None
    percentile: Optional[Decimal] = None