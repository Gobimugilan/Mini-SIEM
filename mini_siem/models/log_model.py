"""ORM model for collected Windows security logs."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class LogRecord(Base):
    """A normalized Windows Security event."""

    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    event_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(255), index=True, default="Unknown")
    computer_name: Mapped[str] = mapped_column(String(255), default="Unknown")
    message: Mapped[str] = mapped_column(Text, default="")

    alerts = relationship("Alert", back_populates="log_record")

    def to_dict(self) -> dict[str, object]:
        """Return a dashboard-friendly representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "username": self.username,
            "computer_name": self.computer_name,
            "message": self.message,
        }
