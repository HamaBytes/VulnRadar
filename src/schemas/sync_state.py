from datetime import datetime
from typing import Optional

from src.schemas.base import BaseSchema


class SyncRunSchema(BaseSchema):
    id: int
    sync_state_id: int
    run_type: str
    start_date: datetime
    end_date: datetime
    status: str = "pending"
    records_processed: int = 0
    records_saved: int = 0
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class SyncStateSchema(BaseSchema):
    id: int
    sync_type: str
    last_modified_watermark: Optional[datetime] = None
    last_sync_date: Optional[datetime] = None
    is_syncing: bool = False
    status: str = "idle"
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    sync_runs: list[SyncRunSchema] = []