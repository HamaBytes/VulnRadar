from sqlalchemy import BigInteger, Column, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class CveTag(Base):
    __tablename__ = "cve_tags"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="CASCADE"), nullable=False)
    value = Column(String(255), nullable=False)

    cve = relationship("Cve", back_populates="tags")


class CveDescription(Base):
    __tablename__ = "cve_descriptions"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="CASCADE"), nullable=False)
    lang = Column(String(10), nullable=False)
    value = Column(Text, nullable=False)

    cve = relationship("Cve", back_populates="descriptions")
