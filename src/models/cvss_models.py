from datetime import datetime

from sqlalchemy import BigInteger, Column, ForeignKey, Float, String, Text, DECIMAL
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class CvssMetricV31(Base):
    __tablename__ = "cvss_metric_v31"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(255))
    metric_type = Column(String(50))
    exploitability_score = Column(DECIMAL(4, 1))
    impact_score = Column(DECIMAL(4, 1))

    cve = relationship("Cve", back_populates="cvss_v31_metrics")
    cvss_data = relationship("CvssDataV31", back_populates="metric", cascade="all, delete-orphan", uselist=False)


class CvssDataV31(Base):
    __tablename__ = "cvss_data_v31"

    id = Column(BigInteger, primary_key=True)
    metric_id = Column(BigInteger, ForeignKey("vulnradar.cvss_metric_v31.id", ondelete="CASCADE"), nullable=False, unique=True)
    version = Column(String(20))
    vector_string = Column(String(255))
    base_score = Column(DECIMAL(4, 1))
    base_severity = Column(String(20))
    attack_vector = Column(String(50))
    attack_complexity = Column(String(50))
    privileges_required = Column(String(50))
    user_interaction = Column(String(50))
    scope = Column(String(50))
    confidentiality_impact = Column(String(50))
    integrity_impact = Column(String(50))
    availability_impact = Column(String(50))

    metric = relationship("CvssMetricV31", back_populates="cvss_data")


class CvssMetricV40(Base):
    __tablename__ = "cvss_metric_v40"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(255))
    metric_type = Column(String(50))

    cve = relationship("Cve", back_populates="cvss_v40_metrics")
    cvss_data = relationship("CvssDataV40", back_populates="metric", cascade="all, delete-orphan", uselist=False)


class CvssDataV40(Base):
    __tablename__ = "cvss_data_v40"

    id = Column(BigInteger, primary_key=True)
    metric_id = Column(BigInteger, ForeignKey("vulnradar.cvss_metric_v40.id", ondelete="CASCADE"), nullable=False, unique=True)
    version = Column(String(20))
    vector_string = Column(String(255))
    base_score = Column(DECIMAL(4, 1))
    base_severity = Column(String(20))
    attack_vector = Column(String(50))
    attack_complexity = Column(String(50))
    attack_requirements = Column(String(50))
    privileges_required = Column(String(50))
    user_interaction = Column(String(50))
    vuln_confidentiality_impact = Column(String(50))
    vuln_integrity_impact = Column(String(50))
    vuln_availability_impact = Column(String(50))
    sub_confidentiality_impact = Column(String(50), nullable=True)
    sub_integrity_impact = Column(String(50), nullable=True)
    sub_availability_impact = Column(String(50), nullable=True)

    metric = relationship("CvssMetricV40", back_populates="cvss_data")
