from typing import Any, Optional

from pydantic import BaseModel, Field


class NvdCveDescription(BaseModel):
    lang: str
    value: str


class NvdCvssDataV2(BaseModel):
    version: Optional[str] = None
    vector_string: Optional[str] = Field(default=None, alias="vectorString")
    base_score: Optional[float] = Field(default=None, alias="baseScore")
    access_vector: Optional[str] = Field(default=None, alias="accessVector")
    access_complexity: Optional[str] = Field(default=None, alias="accessComplexity")
    authentication: Optional[str] = None
    confidentiality_impact: Optional[str] = Field(default=None, alias="confidentialityImpact")
    integrity_impact: Optional[str] = Field(default=None, alias="integrityImpact")
    availability_impact: Optional[str] = Field(default=None, alias="availabilityImpact")


class NvdCvssMetricV2(BaseModel):
    source: Optional[str] = None
    metric_type: Optional[str] = Field(default=None, alias="type")
    cvss_data: Optional[NvdCvssDataV2] = Field(default=None, alias="cvssData")
    base_severity: Optional[str] = Field(default=None, alias="baseSeverity")
    exploitability_score: Optional[float] = Field(default=None, alias="exploitabilityScore")
    impact_score: Optional[float] = Field(default=None, alias="impactScore")
    ac_insuf_info: Optional[bool] = Field(default=None, alias="acInsufInfo")
    obtain_all_privilege: Optional[bool] = Field(default=None, alias="obtainAllPrivilege")
    obtain_user_privilege: Optional[bool] = Field(default=None, alias="obtainUserPrivilege")
    obtain_other_privilege: Optional[bool] = Field(default=None, alias="obtainOtherPrivilege")
    user_interaction_required: Optional[bool] = Field(default=None, alias="userInteractionRequired")


class NvdCvssDataV31(BaseModel):
    version: Optional[str] = None
    vector_string: Optional[str] = Field(default=None, alias="vectorString")
    base_score: Optional[float] = Field(default=None, alias="baseScore")
    base_severity: Optional[str] = Field(default=None, alias="baseSeverity")
    attack_vector: Optional[str] = Field(default=None, alias="attackVector")
    attack_complexity: Optional[str] = Field(default=None, alias="attackComplexity")
    privileges_required: Optional[str] = Field(default=None, alias="privilegesRequired")
    user_interaction: Optional[str] = Field(default=None, alias="userInteraction")
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = Field(default=None, alias="confidentialityImpact")
    integrity_impact: Optional[str] = Field(default=None, alias="integrityImpact")
    availability_impact: Optional[str] = Field(default=None, alias="availabilityImpact")


class NvdCvssMetricV31(BaseModel):
    source: Optional[str] = None
    metric_type: Optional[str] = Field(default=None, alias="type")
    cvss_data: Optional[NvdCvssDataV31] = Field(default=None, alias="cvssData")
    exploitability_score: Optional[float] = Field(default=None, alias="exploitabilityScore")
    impact_score: Optional[float] = Field(default=None, alias="impactScore")


class NvdCvssDataV40(BaseModel):
    version: Optional[str] = None
    vector_string: Optional[str] = Field(default=None, alias="vectorString")
    base_score: Optional[float] = Field(default=None, alias="baseScore")
    base_severity: Optional[str] = Field(default=None, alias="baseSeverity")
    attack_vector: Optional[str] = Field(default=None, alias="attackVector")
    attack_complexity: Optional[str] = Field(default=None, alias="attackComplexity")
    attack_requirements: Optional[str] = Field(default=None, alias="attackRequirements")
    privileges_required: Optional[str] = Field(default=None, alias="privilegesRequired")
    user_interaction: Optional[str] = Field(default=None, alias="userInteraction")
    vuln_confidentiality_impact: Optional[str] = Field(default=None, alias="vulnConfidentialityImpact")
    vuln_integrity_impact: Optional[str] = Field(default=None, alias="vulnIntegrityImpact")
    vuln_availability_impact: Optional[str] = Field(default=None, alias="vulnAvailabilityImpact")
    sub_confidentiality_impact: Optional[str] = Field(default=None, alias="subConfidentialityImpact")
    sub_integrity_impact: Optional[str] = Field(default=None, alias="subIntegrityImpact")
    sub_availability_impact: Optional[str] = Field(default=None, alias="subAvailabilityImpact")


class NvdCvssMetricV40(BaseModel):
    source: Optional[str] = None
    metric_type: Optional[str] = Field(default=None, alias="type")
    cvss_data: Optional[NvdCvssDataV40] = Field(default=None, alias="cvssData")


class NvdCveWeakness(BaseModel):
    source: Optional[str] = None
    weakness_type: Optional[str] = Field(default=None, alias="type")
    description: list[NvdCveDescription] = []


class NvdCpeMatch(BaseModel):
    vulnerable: Optional[bool] = None
    criteria: Optional[str] = None
    match_criteria_id: Optional[str] = Field(default=None, alias="matchCriteriaId")


class NvdNode(BaseModel):
    operator: Optional[str] = None
    negate: Optional[bool] = None
    cpe_match: list[NvdCpeMatch] = Field(default_factory=list, alias="cpeMatch")


class NvdConfiguration(BaseModel):
    nodes: list[NvdNode] = []


class NvdCveReference(BaseModel):
    url: Optional[str] = None
    source: Optional[str] = None


class NvdCve(BaseModel):
    cve_id: str = Field(alias="id")
    source_identifier: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = Field(default=None, alias="lastModified")
    vuln_status: Optional[str] = Field(default=None, alias="vulnStatus")
    cve_tags: list[str] = Field(default_factory=list, alias="cveTags")
    descriptions: list[NvdCveDescription] = []
    metrics_v2: list[NvdCvssMetricV2] = Field(default_factory=list, alias="cvssMetricV2")
    metrics_v31: list[NvdCvssMetricV31] = Field(default_factory=list, alias="cvssMetricV31")
    metrics_v40: list[NvdCvssMetricV40] = Field(default_factory=list, alias="cvssMetricV40")
    weaknesses: list[NvdCveWeakness] = []
    configurations: list[NvdConfiguration] = []
    references: list[NvdCveReference] = []

    def best_score(self) -> tuple[Optional[float], Optional[str], Optional[str]]:
        for m in self.metrics_v40:
            if m.cvss_data and m.cvss_data.base_score is not None:
                return m.cvss_data.base_score, m.cvss_data.base_severity, m.cvss_data.version
        for m in self.metrics_v31:
            if m.cvss_data and m.cvss_data.base_score is not None:
                return m.cvss_data.base_score, m.cvss_data.base_severity, m.cvss_data.version
        for m in self.metrics_v2:
            if m.cvss_data and m.cvss_data.base_score is not None:
                return m.cvss_data.base_score, m.base_severity, m.cvss_data.version
        return None, None, None


class NvdVulnerability(BaseModel):
    cve: NvdCve


class NvdApiResponse(BaseModel):
    vulnerabilities: list[NvdVulnerability] = []