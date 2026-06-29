"""IOC-style removable media monitoring helpers."""

from __future__ import annotations

from models.alert_model import Alert
from models.log_model import LogRecord


class UsbMonitorRule:
    """Detect USB or removable storage references in collected log messages."""

    name = "Removable Media Indicator"
    severity = "Medium"
    keywords = ("usb", "removable storage", "mass storage", "device install")

    def evaluate(self, log_record: LogRecord) -> list[Alert]:
        """Evaluate one log record and return matching alerts."""
        message = (log_record.message or "").lower()
        if not any(keyword in message for keyword in self.keywords):
            return []

        return [
            Alert(
                severity=self.severity,
                title=self.name,
                description=(
                    "Possible removable media activity observed in Windows "
                    f"logs for host '{log_record.computer_name}'."
                ),
                event_id=log_record.event_id,
                related_log_id=log_record.id,
                fingerprint=f"{self.name}:{log_record.id}",
            )
        ]
