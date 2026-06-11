from sqlalchemy import BigInteger, Column, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class CveReference(Base):
    __tablename__ = "cve_references"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    source = Column(String(255))

    cve = relationship("Cve", back_populates="references")
