from datetime import datetime
from decimal import Decimal

from sqlalchemy import BigInteger, DateTime, DECIMAL, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from src.models import *
from src.models.base import Base


class Cve(Base):
    """Core CVE entity with denormalized scores and optimized indexes."""

    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_id: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    source_identifier: Mapped[str | None] = mapped_column(String(255))
    title: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)

    # Denormalized scores for fast filtering/sorting (all CVSS versions)
    cvss_v2_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    cvss_v3_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    cvss_v40_score: Mapped[Decimal | None] = mapped_column(DECIMAL(4, 1))
    severity: Mapped[str | None] = mapped_column(String(20), index=True)

    published_date: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    last_modified_date: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    vuln_status: Mapped[str | None] = mapped_column(String(50), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


    # Relationships — lazy="selectin" prevents N+1 during API serialization
    tags: Mapped[list["CveTag"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    descriptions: Mapped[list["CveDescription"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    cvss_v2_metrics: Mapped[list["CvssMetricV2"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    cvss_v31_metrics: Mapped[list["CvssMetricV31"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    cvss_v40_metrics: Mapped[list["CvssMetricV40"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    weaknesses: Mapped[list["CveWeakness"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    configurations: Mapped[list["CveConfiguration"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    references: Mapped[list["CveReference"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    epss: Mapped[list["Epss"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    exploit_references: Mapped[list["ExploitReference"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    osv_records: Mapped[list["OsvRecord"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    github_advisories: Mapped[list["GithubAdvisory"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    vendor_advisories: Mapped[list["VendorAdvisory"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    project_items: Mapped[list["ProjectItem"]] = relationship(
        back_populates="cve_db", foreign_keys="ProjectItem.cve_db_id", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_cves_published_lastmod", "published_date", "last_modified_date"),
        Index("ix_cves_severity_cvss3", "severity", "cvss_v3_score"),
        Index("ix_cves_status_published", "vuln_status", "published_date"),
    )
