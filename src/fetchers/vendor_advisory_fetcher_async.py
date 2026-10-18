from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class VendorAdvisory(Base):
    __tablename__ = "vendor_advisories"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vendor: Mapped[str | None] = mapped_column(String(100))
    is_available: Mapped[bool] = mapped_column(Boolean, default=False)
    sources: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    details: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    cve: Mapped["Cve"] = relationship(back_populates="vendor_advisories")
