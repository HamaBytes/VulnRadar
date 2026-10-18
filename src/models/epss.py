from decimal import Decimal

from sqlalchemy import BigInteger, DECIMAL, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base
from src.models.cve import Cve


class Epss(Base):
    __tablename__ = "epss"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    epss_score: Mapped[Decimal | None] = mapped_column(DECIMAL(10, 5))
    percentile: Mapped[Decimal | None] = mapped_column(DECIMAL(10, 5))

    cve: Mapped["Cve"] = relationship(back_populates="epss")

    __table_args__ = (Index("ix_epss_score_percentile", "epss_score", "percentile"),)
