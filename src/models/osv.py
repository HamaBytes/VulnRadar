from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class OsvRecord(Base):
    __tablename__ = "osv_records"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    osv_id: Mapped[str | None] = mapped_column(String(100))
    summary: Mapped[str | None] = mapped_column(Text)
    severities: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    cve: Mapped["Cve"] = relationship(back_populates="osv_records")
    references: Mapped[list["OsvReference"]] = relationship(
        back_populates="osv_record", cascade="all, delete-orphan", lazy="selectin"
    )


class OsvReference(Base):
    __tablename__ = "osv_references"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    osv_record_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.osv_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str | None] = mapped_column(String(255))
    title: Mapped[str | None] = mapped_column(String(500))

    osv_record: Mapped["OsvRecord"] = relationship(back_populates="references")
