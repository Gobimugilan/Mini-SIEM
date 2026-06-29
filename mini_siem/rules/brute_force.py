"""Detection rule for repeated failed login activity."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from models.alert_model import Alert
from models.log_model import LogRecord


class BruteForceRule:
    """Detect more than five failed logins within five minutes."""

    name = "Brute Force Login Attempt"
    severity = "High"
    failed_login_event_id = 4625
    threshold = 5
    window = timedelta(minutes=5)

    def evaluate(self, log_record: LogRecord, session: Session) -> list[Alert]:
        """Evaluate one log record against recent failed login history."""
        if log_record.event_id != self.failed_login_event_id:
            return []

        window_start = log_record.timestamp - self.window
        failed_count = (
            session.query(LogRecord)
            .filter(LogRecord.event_id == self.failed_login_event_id)
            .filter(LogRecord.username == log_record.username)
            .filter(LogRecord.timestamp >= window_start)
            .filter(LogRecord.timestamp <= log_record.timestamp)
            .count()
        )

        if failed_count <= self.threshold:
            return []

        fingerprint = (
            f"{self.name}:{log_record.username}:"
            f"{log_record.timestamp.strftime('%Y%m%d%H%M')}"
        )
        return [
            Alert(
                severity=self.severity,
                title=self.name,
                description=(
                    f"{failed_count} failed login attempts for user "
                    f"'{log_record.username}' within 5 minutes."
                ),
                event_id=log_record.event_id,
                related_log_id=log_record.id,
                fingerprint=fingerprint,
            )
        ]
