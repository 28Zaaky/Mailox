from datetime import datetime, timezone
from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def clip_text(value, limit: int):
    """Fit an engine-produced string into a VARCHAR(limit) column.

    Engines build titles from scan data (provider lists, URLs...), so their length
    is unbounded; an overflow would abort the whole scan's final write. Keeps the
    first limit-1 characters and marks the cut with an ellipsis.
    """
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 1] + "…"
    return value


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
