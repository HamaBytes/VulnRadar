from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, DECIMAL, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from src.models import *
from src.models.base import Base


class CvssMetricV2(Base):
    __tablename__ = "cvss_metric_v2"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str | None] = mapped_column(String(255))
    metric_type: Mapped[str | None] = mapped_column(String(50))
    base_severity: Mapped[str | None] = mapped_column(String(20))
    exploitability_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    impact_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    ac_insuf_info: Mapped[bool | None] = mapped_column(Boolean)
    obtain_all_privilege: Mapped[bool | None] = mapped_column(Boolean)
    obtain_user_privilege: Mapped[bool | None] = mapped_column(Boolean)
    obtain_other_privilege: Mapped[bool | None] = mapped_column(Boolean)
    user_interaction_required: Mapped[bool | None] = mapped_column(Boolean)

    cve: Mapped["Cve"] = relationship(back_populates="cvss_v2_metrics")
    cvss_data: Mapped["CvssDataV2"] = relationship(
        back_populates="metric", cascade="all, delete-orphan", uselist=False
    )


class CvssDataV2(Base):
    __tablename__ = "cvss_data_v2"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    metric_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cvss_metric_v2.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    version: Mapped[str | None] = mapped_column(String(20))
    vector_string: Mapped[str | None] = mapped_column(String(255))
    base_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    access_vector: Mapped[str | None] = mapped_column(String(50))
    access_complexity: Mapped[str | None] = mapped_column(String(50))
    authentication: Mapped[str | None] = mapped_column(String(50))
    confidentiality_impact: Mapped[str | None] = mapped_column(String(50))
    integrity_impact: Mapped[str | None] = mapped_column(String(50))
    availability_impact: Mapped[str | None] = mapped_column(String(50))

    metric: Mapped["CvssMetricV2"] = relationship(back_populates="cvss_data")


class CvssMetricV31(Base):
    __tablename__ = "cvss_metric_v31"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str | None] = mapped_column(String(255))
    metric_type: Mapped[str | None] = mapped_column(String(50))
    exploitability_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    impact_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))

    cve: Mapped["Cve"] = relationship(back_populates="cvss_v31_metrics")
    cvss_data: Mapped["CvssDataV31"] = relationship(
        back_populates="metric", cascade="all, delete-orphan", uselist=False
    )


class CvssDataV31(Base):
    __tablename__ = "cvss_data_v31"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    metric_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cvss_metric_v31.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    version: Mapped[str | None] = mapped_column(String(20))
    vector_string: Mapped[str | None] = mapped_column(String(255))
    base_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    base_severity: Mapped[str | None] = mapped_column(String(20))
    attack_vector: Mapped[str | None] = mapped_column(String(50))
    attack_complexity: Mapped[str | None] = mapped_column(String(50))
    privileges_required: Mapped[str | None] = mapped_column(String(50))
    user_interaction: Mapped[str | None] = mapped_column(String(50))
    scope: Mapped[str | None] = mapped_column(String(50))
    confidentiality_impact: Mapped[str | None] = mapped_column(String(50))
    integrity_impact: Mapped[str | None] = mapped_column(String(50))
    availability_impact: Mapped[str | None] = mapped_column(String(50))

    metric: Mapped["CvssMetricV31"] = relationship(back_populates="cvss_data")


class CvssMetricV40(Base):
    __tablename__ = "cvss_metric_v40"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str | None] = mapped_column(String(255))
    metric_type: Mapped[str | None] = mapped_column(String(50))

    cve: Mapped["Cve"] = relationship(back_populates="cvss_v40_metrics")
    cvss_data: Mapped["CvssDataV40"] = relationship(
        back_populates="metric", cascade="all, delete-orphan", uselist=False
    )


class CvssDataV40(Base):
    __tablename__ = "cvss_data_v40"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    metric_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cvss_metric_v40.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    version: Mapped[str | None] = mapped_column(String(20))
    vector_string: Mapped[str | None] = mapped_column(String(255))
    base_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    base_severity: Mapped[str | None] = mapped_column(String(20))
    attack_vector: Mapped[str | None] = mapped_column(String(50))
    attack_complexity: Mapped[str | None] = mapped_column(String(50))
    attack_requirements: Mapped[str | None] = mapped_column(String(50))
    privileges_required: Mapped[str | None] = mapped_column(String(50))
    user_interaction: Mapped[str | None] = mapped_column(String(50))
    vuln_confidentiality_impact: Mapped[str | None] = mapped_column(String(50))
    vuln_integrity_impact: Mapped[str | None] = mapped_column(String(50))
    vuln_availability_impact: Mapped[str | None] = mapped_column(String(50))
    sub_confidentiality_impact: Mapped[str | None] = mapped_column(String(50), nullable=True)
    sub_integrity_impact: Mapped[str | None] = mapped_column(String(50), nullable=True)
    sub_availability_impact: Mapped[str | None] = mapped_column(String(50), nullable=True)

    metric: Mapped["CvssMetricV40"] = relationship(back_populates="cvss_data")
