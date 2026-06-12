from sqlalchemy import BigInteger, Column, DECIMAL, ForeignKey, String
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class Epss(Base):
    __tablename__ = "epss"

    id = Column(BigInteger, primary_key=True)
    cve_db_id = Column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id = Column(String(50), nullable=False, index=True)
    epss_score = Column(DECIMAL(10, 5))
    percentile = Column(DECIMAL(10, 5))

    cve = relationship("Cve", back_populates="epss")

    def to_dict(self):
        return {
            "id": self.id,
            "cve_db_id": self.cve_db_id,
            "cve_id": self.cve_id,
            "epss_score": float(self.epss_score) if self.epss_score is not None else None,
            "percentile": float(self.percentile) if self.percentile is not None else None,
        }
