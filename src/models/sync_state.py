from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class SyncState(Base):
    __tablename__ = "sync_state"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    sync_type: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    last_modified_watermark: Mapped[datetime | None] = mapped_column(DateTime)
    last_sync_date: Mapped[datetime | None] = mapped_column(DateTime)
    is_syncing: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(50), default="idle")
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    sync_runs: Mapped[list["SyncRun"]] = relationship(
        back_populates="sync_state", cascade="all, delete-orphan", lazy="selectin"
    )


class SyncRun(Base):
    __tablename__ = "sync_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    sync_state_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.sync_state.id"),
        nullable=False,
        index=True,
    )
    run_type: Mapped[str] = mapped_column(String(50), nullable=False)
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    records_processed: Mapped[int] = mapped_column(BigInteger, default=0)
    records_saved: Mapped[int] = mapped_column(BigInteger, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    sync_state: Mapped["SyncState"] = relationship(back_populates="sync_runs")
