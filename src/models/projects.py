from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("vulnradar.users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", backref="projects")
    items = relationship("ProjectItem", back_populates="project", cascade="all, delete-orphan")


class ProjectItem(Base):
    __tablename__ = "project_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("vulnradar.projects.id", ondelete="CASCADE"), nullable=False)
    asset_name = Column(String(255), nullable=False)
    ip = Column(String(45), nullable=True)
    hostname = Column(String(255), nullable=True)
    cve_id = Column(String(50), nullable=False)
    cve_db_id = Column(BigInteger, ForeignKey("vulnradar.cves.id", ondelete="SET NULL"), nullable=True)
    criticality = Column(Text, nullable=True)  # low/medium/high/critical/null
    status = Column(Text, nullable=False, default="analysis")  # analysis / mitigation_planned / remediating / risk_accepted
    risk_score = Column(Numeric(5, 2), nullable=True)
    risk_reasons = Column(JSONB, nullable=True)
    ai_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    project = relationship("Project", back_populates="items")
    cve_db = relationship("Cve", backref="project_items")
