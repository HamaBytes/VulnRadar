"""GitHub Advisory ORM models."""

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship
from datetime import datetime

from src.models.db_base import Base


class GithubAdvisory(Base):
    """Stores GitHub Security Advisory enrichment data for a CVE."""

    __tablename__ = "github_advisories"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id = Column(String(50), nullable=False, index=True)
    summary = Column(Text, nullable=True)
    severity = Column(String(50), nullable=True)  # CRITICAL, HIGH, MODERATE, LOW
    package_name = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    cve = relationship("Cve", back_populates="github_advisories")
    references = relationship("GithubAdvisoryReference", back_populates="github_advisory", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cve_db_id": self.cve_db_id,
            "cve_id": self.cve_id,
            "summary": self.summary,
            "severity": self.severity,
            "package_name": self.package_name,
            "references": [ref.to_dict() for ref in self.references],
        }


class GithubAdvisoryReference(Base):
    """Individual reference from a GitHub Advisory."""

    __tablename__ = "github_advisory_references"

    id = Column(BigInteger, primary_key=True)
    github_advisory_id = Column(
        BigInteger,
        ForeignKey("vulnradar.github_advisories.id", ondelete="CASCADE"),
        nullable=False,
    )
    url = Column(Text, nullable=False)
    source = Column(String(255), default="GitHub Advisory")

    github_advisory = relationship("GithubAdvisory", back_populates="references")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "url": self.url,
            "source": self.source,
        }
