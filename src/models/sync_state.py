"""Sync state models for tracking historical import progress."""

from datetime import datetime
from sqlalchemy import BigInteger, Column, DateTime, String, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from src.models.db_base import Base


class SyncState(Base):
    """Tracks overall synchronization state and watermark."""
    
    __tablename__ = "sync_state"
    
    id = Column(BigInteger, primary_key=True)
    sync_type = Column(String(50), unique=True, nullable=False)  # e.g., 'nvd_historical', 'nvd_incremental'
    last_modified_watermark = Column(DateTime, nullable=True)  # Last NVD lastModified timestamp synced
    last_sync_date = Column(DateTime, nullable=True)
    is_syncing = Column(Boolean, default=False)
    status = Column(String(50), default="idle")  # idle, running, completed, failed
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to sync runs
    sync_runs = relationship("SyncRun", back_populates="sync_state", cascade="all, delete-orphan")


class SyncRun(Base):
    """Tracks individual synchronization runs for resumable chunked imports."""
    
    __tablename__ = "sync_runs"
    
    id = Column(BigInteger, primary_key=True)
    sync_state_id = Column(BigInteger, ForeignKey("vulnradar.sync_state.id"), nullable=False)
    run_type = Column(String(50), nullable=False)  # e.g., 'historical_30day_chunk', 'incremental'
    start_date = Column(DateTime, nullable=False)  # Start of date range for this run
    end_date = Column(DateTime, nullable=False)  # End of date range for this run
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    records_processed = Column(BigInteger, default=0)
    records_saved = Column(BigInteger, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship to sync state
    sync_state = relationship("SyncState", back_populates="sync_runs")
