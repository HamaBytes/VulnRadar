from sqlalchemy import BigInteger, Boolean, Column, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class CveConfiguration(Base):
    __tablename__ = "cve_configurations"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="CASCADE"), nullable=False)

    cve = relationship("Cve", back_populates="configurations")
    nodes = relationship("CveNode", back_populates="configuration", cascade="all, delete-orphan")


class CveNode(Base):
    __tablename__ = "cve_nodes"

    id = Column(BigInteger, primary_key=True)
    configuration_id = Column(BigInteger, ForeignKey("vulnradar.cve_configurations.id", ondelete="CASCADE"), nullable=False)
    operator = Column(String(20))
    negate = Column(Boolean)

    configuration = relationship("CveConfiguration", back_populates="nodes")
    cpe_matches = relationship("CpeMatch", back_populates="node", cascade="all, delete-orphan")


class CpeMatch(Base):
    __tablename__ = "cpe_matches"

    id = Column(BigInteger, primary_key=True)
    node_id = Column(BigInteger, ForeignKey("vulnradar.cve_nodes.id", ondelete="CASCADE"), nullable=False)
    vulnerable = Column(Boolean)
    criteria = Column(Text)
    match_criteria_id = Column(String(100))

    node = relationship("CveNode", back_populates="cpe_matches")
