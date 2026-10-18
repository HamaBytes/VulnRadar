from decimal import Decimal
from typing import Optional

from src.schemas.base import BaseSchema


class CvssDataV2Schema(BaseSchema):
    id: int
    version: Optional[str] = None
    vector_string: Optional[str] = None
    base_score: Optional[Decimal] = None
    access_vector: Optional[str] = None
    access_complexity: Optional[str] = None
    authentication: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None


class CvssMetricV2Schema(BaseSchema):
    id: int
    cve_db_id: int
    source: Optional[str] = None
    metric_type: Optional[str] = None
    base_severity: Optional[str] = None
    exploitability_score: Optional[Decimal] = None
    impact_score: Optional[Decimal] = None
    ac_insuf_info: Optional[bool] = None
    obtain_all_privilege: Optional[bool] = None
    obtain_user_privilege: Optional[bool] = None
    obtain_other_privilege: Optional[bool] = None
    user_interaction_required: Optional[bool] = None
    cvss_data: Optional[CvssDataV2Schema] = None


class CvssDataV31Schema(BaseSchema):
    id: int
    version: Optional[str] = None
    vector_string: Optional[str] = None
    base_score: Optional[Decimal] = None
    base_severity: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None


class CvssMetricV31Schema(BaseSchema):
    id: int
    cve_db_id: int
    source: Optional[str] = None
    metric_type: Optional[str] = None
    exploitability_score: Optional[Decimal] = None
    impact_score: Optional[Decimal] = None
    cvss_data: Optional[CvssDataV31Schema] = None


class CvssDataV40Schema(BaseSchema):
    id: int
    version: Optional[str] = None
    vector_string: Optional[str] = None
    base_score: Optional[Decimal] = None
    base_severity: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    attack_requirements: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    vuln_confidentiality_impact: Optional[str] = None
    vuln_integrity_impact: Optional[str] = None
    vuln_availability_impact: Optional[str] = None
    sub_confidentiality_impact: Optional[str] = None
    sub_integrity_impact: Optional[str] = None
    sub_availability_impact: Optional[str] = None


class CvssMetricV40Schema(BaseSchema):
    id: int
    cve_db_id: int
    source: Optional[str] = None
    metric_type: Optional[str] = None
    cvss_data: Optional[CvssDataV40Schema] = None