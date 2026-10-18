from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class GithubAdvisory(Base):
    __tablename__ = "github_advisories"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    summary: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(50))
    package_name: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    cve: Mapped["Cve"] = relationship(back_populates="github_advisories")
    references: Mapped[list["GithubAdvisoryReference"]] = relationship(
        back_populates="github_advisory", cascade="all, delete-orphan", lazy="selectin"
    )


class GithubAdvisoryReference(Base):
    __tablename__ = "github_advisory_references"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    github_advisory_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.github_advisories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(String(255), default="GitHub Advisory")

    github_advisory: Mapped["GithubAdvisory"] = relationship(back_populates="references")
