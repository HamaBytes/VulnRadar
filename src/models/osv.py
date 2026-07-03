"""OSV (Open Source Vulnerabilities) ORM models."""

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from datetime import datetime

from src.models.db_base import Base


class OsvRecord(Base):
    """Stores OSV enrichment data for a CVE."""

    __tablename__ = "osv_records"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id = Column(String(50), nullable=False, index=True)
    osv_id = Column(String(100), nullable=True)  # OSV-specific identifier
    summary = Column(Text, nullable=True)
    severities = Column(JSONB, nullable=True)  # List of "type:score" strings
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    cve = relationship("Cve", back_populates="osv_records")
    references = relationship("OsvReference", back_populates="osv_record", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cve_db_id": self.cve_db_id,
            "cve_id": self.cve_id,
            "osv_id": self.osv_id,
            "summary": self.summary,
            "severities": self.severities or [],
            "references": [ref.to_dict() for ref in self.references],
        }


class OsvReference(Base):
    """Individual reference from an OSV record."""

    __tablename__ = "osv_references"

    id = Column(BigInteger, primary_key=True)
    osv_record_id = Column(
        BigInteger,
        ForeignKey("vulnradar.osv_records.id", ondelete="CASCADE"),
        nullable=False,
    )
    url = Column(Text, nullable=False)
    source_id = Column(String(255), nullable=True)
    title = Column(String(500), nullable=True)

    osv_record = relationship("OsvRecord", back_populates="references")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "url": self.url,
            "source_id": self.source_id,
            "title": self.title,
        }
