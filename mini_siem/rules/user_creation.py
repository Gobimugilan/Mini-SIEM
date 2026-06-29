"""Detection rule for Windows account creation events."""

from __future__ import annotations

from models.alert_model import Alert
from models.log_model import LogRecord


class UserCreationRule:
    """Detect new local or domain user account creation."""

    name = "New User Account Created"
    event_id = 4720
    severity = "Medium"

    def evaluate(self, log_record: LogRecord) -> list[Alert]:
        """Evaluate one log record and return matching alerts."""
        if log_record.event_id != self.event_id:
            return []

        return [
            Alert(
                severity=self.severity,
                title=self.name,
                description=(
                    f"User account creation detected on "
                    f"'{log_record.computer_name}'. Subject user: "
                    f"'{log_record.username}'."
                ),
                event_id=log_record.event_id,
                related_log_id=log_record.id,
                fingerprint=f"{self.name}:{log_record.id}",
            )
        ]
