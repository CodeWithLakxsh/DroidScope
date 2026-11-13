"""SQLAlchemy declarative base and shared column helpers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, MetaData, String, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Explicit naming convention so Alembic can autogenerate stable constraint names.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def new_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(UTC)


class IdMixin:
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class StrEnumType(TypeDecorator):
    """Store a StrEnum as VARCHAR and return it as the enum, not a bare string.

    Without this, a value read back from the database is a plain ``str``, so
    ``row.severity.value`` raises AttributeError while the same expression works
    on a freshly constructed object. Coercing on load removes that whole class
    of bug and keeps the column a plain VARCHAR, so no migration is needed.
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_class: type[StrEnum], length: int = 32, **kwargs: Any) -> None:
        self.enum_class = enum_class
        super().__init__(length=length, **kwargs)

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, self.enum_class):
            return value.value
        # Validate on the way in so an unknown value cannot reach the column.
        return self.enum_class(str(value)).value

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        try:
            return self.enum_class(value)
        except ValueError:
            # A row written by an older version with a since-removed member
            # must not break reads.
            return value
