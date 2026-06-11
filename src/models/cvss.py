from sqlalchemy import BigInteger, Boolean, Column, DECIMAL, ForeignKey, String
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class CvssMetricV2(Base):
    __tablename__ = "cvss_metric_v2"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(255))
    metric_type = Column(String(50))
    base_severity = Column(String(20))
    exploitability_score = Column(DECIMAL(4, 1))
    impact_score = Column(DECIMAL(4, 1))
    ac_insuf_info = Column(Boolean)
    obtain_all_privilege = Column(Boolean)
    obtain_user_privilege = Column(Boolean)
    obtain_other_privilege = Column(Boolean)
    user_interaction_required = Column(Boolean)

    cve = relationship("Cve", back_populates="cvss_v2_metrics")
    cvss_data = relationship(
        "CvssDataV2",
        back_populates="metric",
        cascade="all, delete-orphan",
        uselist=False,
    )


class CvssDataV2(Base):
    __tablename__ = "cvss_data_v2"

    id = Column(BigInteger, primary_key=True)
    metric_id = Column(BigInteger, ForeignKey("vulnradar.cvss_metric_v2.id", ondelete="CASCADE"), nullable=False, unique=True)
    version = Column(String(20))
    vector_string = Column(String(255))
    base_score = Column(DECIMAL(4, 1))
    access_vector = Column(String(50))
    access_complexity = Column(String(50))
    authentication = Column(String(50))
    confidentiality_impact = Column(String(50))
    integrity_impact = Column(String(50))
    availability_impact = Column(String(50))

    metric = relationship("CvssMetricV2", back_populates="cvss_data")
