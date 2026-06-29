"""Rule engine, IOC matching, alert deduplication, and retention jobs."""

from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import desc
from sqlalchemy.orm import Session

from ai_analyzer import OllamaSecurityAnalyst
from database import DatabaseManager, init_db
from models.alert_model import Alert
from models.log_model import LogRecord
from rules import BruteForceRule, FailedLoginRule, UsbMonitorRule, UserCreationRule


LOGGER = logging.getLogger(__name__)


class IOCMatcher:
    """Simple indicator matcher for usernames, hosts, and log messages."""

    def __init__(self, indicators: list[str] | None = None) -> None:
        self.indicators = indicators or [
            "mimikatz",
            "powershell -enc",
            "cobalt strike",
            "rundll32",
            "suspicious",
        ]

    def evaluate(self, log_record: LogRecord) -> list[Alert]:
        """Return alerts when known indicators are present."""
        haystack = " ".join(
            [
                log_record.username or "",
                log_record.computer_name or "",
                log_record.message or "",
            ]
        ).lower()

        matches = [ioc for ioc in self.indicators if ioc.lower() in haystack]
        if not matches:
            return []

        return [
            Alert(
                severity="Critical",
                title="IOC Match Detected",
                description=(
                    "Known suspicious indicator(s) matched in the log: "
                    f"{', '.join(matches)}."
                ),
                event_id=log_record.event_id,
                related_log_id=log_record.id,
                fingerprint=f"IOC:{log_record.id}:{','.join(matches)}",
            )
        ]


class AccountLockoutRule:
    """Detect Windows account lockout events."""

    name = "Account Lockout"
    event_id = 4740
    severity = "High"

    def evaluate(self, log_record: LogRecord) -> list[Alert]:
        """Evaluate one log record and return matching alerts."""
        if log_record.event_id != self.event_id:
            return []

        return [
            Alert(
                severity=self.severity,
                title=self.name,
                description=(
                    f"Account '{log_record.username}' was locked out on "
                    f"'{log_record.computer_name}'."
                ),
                event_id=log_record.event_id,
                related_log_id=log_record.id,
                fingerprint=f"{self.name}:{log_record.id}",
            )
        ]


class DetectionEngine:
    """Coordinate rules, deduplication, AI analysis, and retention."""

    def __init__(
        self,
        db: DatabaseManager,
        ai_analyzer: OllamaSecurityAnalyst | None = None,
        dedup_window_minutes: int = 10,
        retention_days: int = 30,
    ) -> None:
        self.db = db
        self.rules = [
            FailedLoginRule(),
            BruteForceRule(),
            UserCreationRule(),
            AccountLockoutRule(),
            UsbMonitorRule(),
        ]
        self.ioc_matcher = IOCMatcher()
        self.ai_analyzer = ai_analyzer or OllamaSecurityAnalyst(enabled=False)
        self.dedup_window = timedelta(minutes=dedup_window_minutes)
        self.retention_days = retention_days

    def run(self, limit: int = 1000, include_ai: bool = True) -> int:
        """Run detections against recent logs and return created alert count."""
        created = 0
        self.db.enforce_retention(self.retention_days)

        with self.db.session_scope() as session:
            logs = (
                session.query(LogRecord)
                .order_by(desc(LogRecord.timestamp))
                .limit(limit)
                .all()
            )
            for log_record in reversed(logs):
                alerts = self._evaluate_log(log_record, session)
                for alert in alerts:
                    if self._is_duplicate(alert, session):
                        continue
                    if include_ai:
                        self._attach_ai_analysis(alert, log_record)
                    session.add(alert)
                    created += 1

        return created

    def _evaluate_log(self, log_record: LogRecord, session: Session) -> list[Alert]:
        """Evaluate all rules for a single log record."""
        alerts: list[Alert] = []
        for rule in self.rules:
            try:
                if isinstance(rule, BruteForceRule):
                    alerts.extend(rule.evaluate(log_record, session))
                else:
                    alerts.extend(rule.evaluate(log_record))
            except Exception as exc:
                LOGGER.exception("Rule %s failed: %s", rule.name, exc)

        alerts.extend(self.ioc_matcher.evaluate(log_record))
        return alerts

    def _is_duplicate(self, alert: Alert, session: Session) -> bool:
        """Return True when a similar alert already exists recently."""
        existing = (
            session.query(Alert)
            .filter(Alert.fingerprint == alert.fingerprint)
            .first()
        )
        return existing is not None

    def _attach_ai_analysis(self, alert: Alert, log_record: LogRecord) -> None:
        """Generate and attach AI analysis to an alert."""
        analysis = self.ai_analyzer.analyze(alert, log_record)
        self.ai_analyzer.apply_to_alert(alert, analysis)


def main() -> None:
    """CLI entry point for manual detection runs."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    db = init_db()
    engine = DetectionEngine(db)
    created = engine.run(include_ai=False)
    LOGGER.info("Created %s alerts.", created)


if __name__ == "__main__":
    main()
