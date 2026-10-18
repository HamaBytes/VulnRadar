from datetime import datetime
from decimal import Decimal

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnradar.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="projects")
    items: Mapped[list["ProjectItem"]] = relationship(
        back_populates="project", cascade="all, delete-orphan", lazy="selectin"
    )


class ProjectItem(Base):
    __tablename__ = "project_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnradar.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(45))
    hostname: Mapped[str | None] = mapped_column(String(255))
    cve_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    cve_db_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    criticality: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="analysis")
    risk_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    risk_reasons: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ai_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    project: Mapped["Project"] = relationship(back_populates="items")
    cve_db: Mapped["Cve | None"] = relationship(
        back_populates="project_items", foreign_keys=[cve_db_id]
    )
