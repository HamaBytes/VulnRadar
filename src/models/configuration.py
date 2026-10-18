from sqlalchemy import BigInteger, Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from models import *
from src.models.base import Base


# noinspection PyTypeHints
class CveConfiguration(Base):
    __tablename__ = "cve_configurations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cve_db_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    cve: Mapped["Cve"] = relationship(back_populates="configurations")
    nodes: Mapped[list["CveNode"]] = relationship(
        back_populates="configuration", cascade="all, delete-orphan", lazy="selectin"
    )


class CveNode(Base):
    __tablename__ = "cve_nodes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    configuration_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cve_configurations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    operator: Mapped[str | None] = mapped_column(String(20))
    negate: Mapped[bool | None] = mapped_column(Boolean)

    configuration: Mapped["CveConfiguration"] = relationship(back_populates="nodes")
    cpe_matches: Mapped[list["CpeMatch"]] = relationship(
        back_populates="node", cascade="all, delete-orphan", lazy="selectin"
    )


class CpeMatch(Base):
    __tablename__ = "cpe_matches"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    node_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("vulnradar.cve_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vulnerable: Mapped[bool | None] = mapped_column(Boolean)
    criteria: Mapped[str | None] = mapped_column(Text)
    match_criteria_id: Mapped[str | None] = mapped_column(String(100))

    node: Mapped["CveNode"] = relationship(back_populates="cpe_matches")
