from sqlalchemy import BigInteger, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class CveWeakness(Base):
    __tablename__ = "cve_weaknesses"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str | None] = mapped_column(String(255))
    weakness_type: Mapped[str | None] = mapped_column(String(50))

    cve: Mapped["Cve"] = relationship(back_populates="weaknesses")
    descriptions: Mapped[list["CveWeaknessDescription"]] = relationship(
        back_populates="weakness", cascade="all, delete-orphan", lazy="selectin"
    )


class CveWeaknessDescription(Base):
    __tablename__ = "cve_weakness_descriptions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    weakness_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cve_weaknesses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    lang: Mapped[str] = mapped_column(String(10), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)

    weakness: Mapped["CveWeakness"] = relationship(back_populates="descriptions")
