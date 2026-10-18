from datetime import datetime
from decimal import Decimal
from typing import Optional

from src.schemas.base import BaseSchema
from src.schemas.cve_details import CveDescriptionSchema, CveTagSchema
from src.schemas.cvss import CvssMetricV2Schema, CvssMetricV31Schema, CvssMetricV40Schema
from src.schemas.weakness import CveWeaknessSchema
from src.schemas.configuration import CveConfigurationSchema
from src.schemas.reference import CveReferenceSchema
from src.schemas.exploit import ExploitReferenceSchema
from src.schemas.epss import EpssSchema
from src.schemas.osv import OsvRecordSchema
from src.schemas.github_advisory import GithubAdvisorySchema
from src.schemas.vendor_advisory import VendorAdvisorySchema


class CveListItemSchema(BaseSchema):
    """Lightweight schema for list views."""
    id: int
    cve_id: str
    title: Optional[str] = None
    severity: Optional[str] = None
    cvss_v3_score: Optional[Decimal] = None
    cvss_v40_score: Optional[Decimal] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    vuln_status: Optional[str] = None


class CveDetailSchema(BaseSchema):
    """Full schema for detail views."""
    id: int
    cve_id: str
    source_identifier: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    cvss_v2_score: Optional[Decimal] = None
    cvss_v3_score: Optional[Decimal] = None
    cvss_v40_score: Optional[Decimal] = None
    severity: Optional[str] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    vuln_status: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    # Nested relationships
    tags: list[CveTagSchema] = []
    descriptions: list[CveDescriptionSchema] = []
    cvss_v2_metrics: list[CvssMetricV2Schema] = []
    cvss_v31_metrics: list[CvssMetricV31Schema] = []
    cvss_v40_metrics: list[CvssMetricV40Schema] = []
    weaknesses: list[CveWeaknessSchema] = []
    configurations: list[CveConfigurationSchema] = []
    references: list[CveReferenceSchema] = []
    epss: list[EpssSchema] = []
    exploit_references: list[ExploitReferenceSchema] = []
    osv_records: list[OsvRecordSchema] = []
    github_advisories: list[GithubAdvisorySchema] = []
    vendor_advisories: list[VendorAdvisorySchema] = []