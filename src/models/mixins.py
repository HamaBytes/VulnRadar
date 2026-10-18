from datetime import datetime
from typing import Any

from sqlalchemy import inspect
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import CreatedAt, UpdatedAt


class TimestampMixin:
    """Adds created_at and updated_at to any model."""
    created_at: Mapped[CreatedAt]
    updated_at: Mapped[UpdatedAt]


class SerializeMixin:
    """Provides a standard to_dict() using SQLAlchemy inspection."""
    def to_dict(self, exclude: set[str] | None = None) -> dict[str, Any]:
        exclude = exclude or set()
        mapper = inspect(self.__class__)
        return {
            col.key: getattr(self, col.key)
            for col in mapper.columns
            if col.key not in exclude
        }