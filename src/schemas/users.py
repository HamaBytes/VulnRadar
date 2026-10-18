from datetime import datetime
from typing import Optional

from src.schemas.base import BaseSchema


class UserSchema(BaseSchema):
    id: int
    email: str
    created_at: Optional[datetime] = None
    is_active: bool = True