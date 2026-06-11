from sqlalchemy import BigInteger, Column, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class CveWeakness(Base):
    __tablename__ = "cve_weaknesses"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(255))
    weakness_type = Column(String(50))

    cve = relationship("Cve", back_populates="weaknesses")
    descriptions = relationship(
        "CveWeaknessDescription",
        back_populates="weakness",
        cascade="all, delete-orphan",
    )


class CveWeaknessDescription(Base):
    __tablename__ = "cve_weakness_descriptions"

    id = Column(BigInteger, primary_key=True)
    weakness_id = Column(BigInteger, ForeignKey("vulnradar.cve_weaknesses.id", ondelete="CASCADE"), nullable=False)
    lang = Column(String(10), nullable=False)
    value = Column(Text, nullable=False)

    weakness = relationship("CveWeakness", back_populates="descriptions")
