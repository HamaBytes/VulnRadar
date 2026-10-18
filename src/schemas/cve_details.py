from src.schemas.base import BaseSchema


class CveTagSchema(BaseSchema):
    id: int
    cve_db_id: int
    value: str


class CveDescriptionSchema(BaseSchema):
    id: int
    cve_db_id: int
    lang: str
    value: str