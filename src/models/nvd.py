from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CveDescription:
    lang: str
    value: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CveDescription":
        return cls(lang=data.get("lang", ""), value=data.get("value", ""))


@dataclass(slots=True)
class CvssDataV2:
    version: str | None = None
    vector_string: str | None = None
    base_score: float | None = None
    access_vector: str | None = None
    access_complexity: str | None = None
    authentication: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CvssDataV2":
        return cls(
            version=data.get("version"),
            vector_string=data.get("vectorString"),
            base_score=data.get("baseScore"),
            access_vector=data.get("accessVector"),
            access_complexity=data.get("accessComplexity"),
            authentication=data.get("authentication"),
            confidentiality_impact=data.get("confidentialityImpact"),
            integrity_impact=data.get("integrityImpact"),
            availability_impact=data.get("availabilityImpact"),
        )


@dataclass(slots=True)
class CvssMetricV2:
    source: str | None = None
    metric_type: str | None = None
    cvss_data: CvssDataV2 | None = None
    base_severity: str | None = None
    exploitability_score: float | None = None
    impact_score: float | None = None
    ac_insuf_info: bool | None = None
    obtain_all_privilege: bool | None = None
    obtain_user_privilege: bool | None = None
    obtain_other_privilege: bool | None = None
    user_interaction_required: bool | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CvssMetricV2":
        return cls(
            source=data.get("source"),
            metric_type=data.get("type"),
            cvss_data=CvssDataV2.from_dict(data.get("cvssData", {})) if data.get("cvssData") else None,
            base_severity=data.get("baseSeverity"),
            exploitability_score=data.get("exploitabilityScore"),
            impact_score=data.get("impactScore"),
            ac_insuf_info=data.get("acInsufInfo"),
            obtain_all_privilege=data.get("obtainAllPrivilege"),
            obtain_user_privilege=data.get("obtainUserPrivilege"),
            obtain_other_privilege=data.get("obtainOtherPrivilege"),
            user_interaction_required=data.get("userInteractionRequired"),
        )


@dataclass(slots=True)
class CveWeakness:
    source: str | None = None
    weakness_type: str | None = None
    description: list[CveDescription] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CveWeakness":
        return cls(
            source=data.get("source"),
            weakness_type=data.get("type"),
            description=[CveDescription.from_dict(item) for item in data.get("description", [])],
        )


@dataclass(slots=True)
class CpeMatch:
    vulnerable: bool | None = None
    criteria: str | None = None
    match_criteria_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CpeMatch":
        return cls(
            vulnerable=data.get("vulnerable"),
            criteria=data.get("criteria"),
            match_criteria_id=data.get("matchCriteriaId"),
        )


@dataclass(slots=True)
class NvdNode:
    operator: str | None = None
    negate: bool | None = None
    cpe_match: list[CpeMatch] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NvdNode":
        return cls(
            operator=data.get("operator"),
            negate=data.get("negate"),
            cpe_match=[CpeMatch.from_dict(item) for item in data.get("cpeMatch", [])],
        )


@dataclass(slots=True)
class NvdConfiguration:
    nodes: list[NvdNode] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NvdConfiguration":
        return cls(nodes=[NvdNode.from_dict(item) for item in data.get("nodes", [])])


@dataclass(slots=True)
class CveReference:
    url: str | None = None
    source: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CveReference":
        return cls(url=data.get("url"), source=data.get("source"))


@dataclass(slots=True)
class NvdCve:
    cve_id: str
    source_identifier: str | None = None
    published: str | None = None
    last_modified: str | None = None
    vuln_status: str | None = None
    cve_tags: list[str] = field(default_factory=list)
    descriptions: list[CveDescription] = field(default_factory=list)
    metrics: list[CvssMetricV2] = field(default_factory=list)
    weaknesses: list[CveWeakness] = field(default_factory=list)
    configurations: list[NvdConfiguration] = field(default_factory=list)
    references: list[CveReference] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NvdCve":
        metrics_data = data.get("metrics", {}).get("cvssMetricV2", [])
        return cls(
            cve_id=data.get("id", ""),
            source_identifier=data.get("sourceIdentifier"),
            published=data.get("published"),
            last_modified=data.get("lastModified"),
            vuln_status=data.get("vulnStatus"),
            cve_tags=list(data.get("cveTags", [])),
            descriptions=[CveDescription.from_dict(item) for item in data.get("descriptions", [])],
            metrics=[CvssMetricV2.from_dict(item) for item in metrics_data],
            weaknesses=[CveWeakness.from_dict(item) for item in data.get("weaknesses", [])],
            configurations=[NvdConfiguration.from_dict(item) for item in data.get("configurations", [])],
            references=[CveReference.from_dict(item) for item in data.get("references", [])],
        )


@dataclass(slots=True)
class NvdVulnerability:
    cve: NvdCve

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NvdVulnerability":
        return cls(cve=NvdCve.from_dict(data.get("cve", {})))


@dataclass(slots=True)
class NvdApiResponse:
    vulnerabilities: list[NvdVulnerability] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NvdApiResponse":
        return cls(
            vulnerabilities=[NvdVulnerability.from_dict(item) for item in data.get("vulnerabilities", [])],
        )
