"""ORM model for security alerts and optional AI analysis."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class Alert(Base):
    """A generated security alert."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    event_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    related_log_id: Mapped[int | None] = mapped_column(
        ForeignKey("logs.id"),
        nullable=True,
        index=True,
    )
    fingerprint: Mapped[str] = mapped_column(String(255), index=True, nullable=False)

    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_severity_assessment: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_investigation_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_mitre_mapping: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_recommended_remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    log_record = relationship("LogRecord", back_populates="alerts")

    def to_dict(self) -> dict[str, object]:
        """Return a dashboard-friendly representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "event_id": self.event_id,
            "related_log_id": self.related_log_id,
            "ai_summary": self.ai_summary,
            "ai_severity_assessment": self.ai_severity_assessment,
            "ai_investigation_steps": self.ai_investigation_steps,
            "ai_mitre_mapping": self.ai_mitre_mapping,
            "ai_recommended_remediation": self.ai_recommended_remediation,
        }
