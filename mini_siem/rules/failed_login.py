"""Detection rule for Windows failed logon events."""

from __future__ import annotations

from models.alert_model import Alert
from models.log_model import LogRecord


class FailedLoginRule:
    """Create a low severity alert for each failed Windows logon."""

    name = "Failed Login Detection"
    event_id = 4625
    severity = "Low"

    def evaluate(self, log_record: LogRecord) -> list[Alert]:
        """Evaluate one log record and return matching alerts."""
        if log_record.event_id != self.event_id:
            return []

        return [
            Alert(
                severity=self.severity,
                title=self.name,
                description=(
                    f"Failed login detected for user '{log_record.username}' "
                    f"on host '{log_record.computer_name}'."
                ),
                event_id=log_record.event_id,
                related_log_id=log_record.id,
                fingerprint=f"{self.name}:{log_record.id}",
            )
        ]
