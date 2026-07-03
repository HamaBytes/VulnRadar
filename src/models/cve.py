from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, DECIMAL, String, Text
from sqlalchemy.orm import relationship

from src.models.db_base import Base
import src.models.cve_details  # register CveDescription, CveTag
import src.models.cvss_models  # register CVSS model classes with SQLAlchemy
import src.models.configuration  # register CveConfiguration, CveNode, CpeMatch
import src.models.epss  # register Epss
import src.models.exploit  # register ExploitReference
import src.models.reference  # register CveReference
import src.models.weakness  # register CveWeakness, CveWeaknessDescription
import src.models.osv  # register OsvRecord, OsvReference
import src.models.github_advisory  # register GithubAdvisory, GithubAdvisoryReference
import src.models.vendor_advisory  # register VendorAdvisory


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

    # Existing relationships
    tags = relationship("CveTag", back_populates="cve", cascade="all, delete-orphan")
    descriptions = relationship("CveDescription", back_populates="cve", cascade="all, delete-orphan")
    cvss_v2_metrics = relationship("CvssMetricV2", back_populates="cve", cascade="all, delete-orphan")
    cvss_v31_metrics = relationship("CvssMetricV31", back_populates="cve", cascade="all, delete-orphan")
    cvss_v40_metrics = relationship("CvssMetricV40", back_populates="cve", cascade="all, delete-orphan")
    weaknesses = relationship("CveWeakness", back_populates="cve", cascade="all, delete-orphan")
    configurations = relationship("CveConfiguration", back_populates="cve", cascade="all, delete-orphan")
    references = relationship("CveReference", back_populates="cve", cascade="all, delete-orphan")
    epss = relationship("Epss", back_populates="cve", cascade="all, delete-orphan")
    exploit_references = relationship("ExploitReference", back_populates="cve", cascade="all, delete-orphan")

    # NEW: Enrichment data relationships
    osv_records = relationship("OsvRecord", back_populates="cve", cascade="all, delete-orphan")
    github_advisories = relationship("GithubAdvisory", back_populates="cve", cascade="all, delete-orphan")
    vendor_advisories = relationship("VendorAdvisory", back_populates="cve", cascade="all, delete-orphan")

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
