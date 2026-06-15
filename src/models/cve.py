from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, DECIMAL, String, Text
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class Cve(Base):
    __tablename__ = "cves"

    id = Column(BigInteger, primary_key=True)
    cve_id = Column(String(50), unique=True, nullable=False)
    source_identifier = Column(String(255))
    title = Column(String(500))
    description = Column(Text)
    cvss_v3_score = Column(DECIMAL(4, 1))
    severity = Column(String(20))
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    vuln_status = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)

    tags = relationship("CveTag", back_populates="cve", cascade="all, delete-orphan")
    descriptions = relationship("CveDescription", back_populates="cve", cascade="all, delete-orphan")
    cvss_v2_metrics = relationship("CvssMetricV2", back_populates="cve", cascade="all, delete-orphan")
    weaknesses = relationship("CveWeakness", back_populates="cve", cascade="all, delete-orphan")
    configurations = relationship("CveConfiguration", back_populates="cve", cascade="all, delete-orphan")
    references = relationship("CveReference", back_populates="cve", cascade="all, delete-orphan")
    epss = relationship("Epss", back_populates="cve", cascade="all, delete-orphan")
    exploit_references = relationship("ExploitReference", back_populates="cve", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "source_identifier": self.source_identifier,
            "title": self.title,
            "description": self.description,
            "cvss_v3_score": float(self.cvss_v3_score) if self.cvss_v3_score is not None else None,
            "severity": self.severity,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified_date": self.last_modified_date.isoformat() if self.last_modified_date else None,
            "vuln_status": self.vuln_status,
        }
