from typing import Optional

from src.schemas.base import BaseSchema


class CpeMatchSchema(BaseSchema):
    id: int
    node_id: int
    vulnerable: Optional[bool] = None
    criteria: Optional[str] = None
    match_criteria_id: Optional[str] = None


class CveNodeSchema(BaseSchema):
    id: int
    configuration_id: int
    operator: Optional[str] = None
    negate: Optional[bool] = None
    cpe_matches: list[CpeMatchSchema] = []


class CveConfigurationSchema(BaseSchema):
    id: int
    cve_db_id: int
    nodes: list[CveNodeSchema] = []