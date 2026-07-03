"""Vendor Advisory ORM models."""

from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from datetime import datetime

from src.models.db_base import Base


class VendorAdvisory(Base):
    """Stores vendor security advisory enrichment data for a CVE."""

    __tablename__ = "vendor_advisories"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id = Column(String(50), nullable=False, index=True)
    vendor = Column(String(100), nullable=True)  # e.g., "microsoft", "oracle"
    is_available = Column(Boolean, default=False)
    sources = Column(JSONB, nullable=True)  # List of source strings
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    cve = relationship("Cve", back_populates="vendor_advisories")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cve_db_id": self.cve_db_id,
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "is_available": self.is_available,
            "sources": self.sources or [],
            "details": self.details,
        }
