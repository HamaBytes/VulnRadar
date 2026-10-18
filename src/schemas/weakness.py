from typing import Optional

from src.schemas.base import BaseSchema


class CveWeaknessDescriptionSchema(BaseSchema):
    id: int
    weakness_id: int
    lang: str
    value: str


class CveWeaknessSchema(BaseSchema):
    id: int
    cve_db_id: int
    source: Optional[str] = None
    weakness_type: Optional[str] = None
    descriptions: list[CveWeaknessDescriptionSchema] = []