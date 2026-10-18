from datetime import datetime
from typing import Annotated

from sqlalchemy import BigInteger, DateTime, MetaData, String, func
from sqlalchemy.orm import declarative_base, mapped_column

# Naming convention for Alembic auto-generation
convention = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

Base = declarative_base(
    metadata=MetaData(schema="vulnradar", naming_convention=convention)
)
