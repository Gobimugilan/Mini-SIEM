"""Database access layer for the Mini SIEM project."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Generator, Iterable

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "logs.db"
DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"


class Base(DeclarativeBase):
    """Base class for SQLAlchemy ORM models."""


class DatabaseManager:
    """Manage SQLite connections and common SIEM persistence operations."""

    def __init__(self, database_url: str = DATABASE_URL) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            database_url,
            connect_args={"check_same_thread": False},
            future=True,
        )
        self.session_factory = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            autoflush=False,
            future=True,
        )

    def initialize(self) -> None:
        """Create database tables if they do not already exist."""
        from models.alert_model import Alert  # noqa: F401
        from models.log_model import LogRecord  # noqa: F401

        Base.metadata.create_all(self.engine)

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Provide a transactional session scope."""
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def add_log(self, log_record: "LogRecord") -> "LogRecord":
        """Persist one log record and return it with its database id."""
        with self.session_scope() as session:
            session.add(log_record)
            session.flush()
            session.refresh(log_record)
            return log_record

    def add_logs(self, log_records: Iterable["LogRecord"]) -> int:
        """Persist multiple log records and return the inserted count."""
        records = list(log_records)
        if not records:
            return 0

        with self.session_scope() as session:
            session.add_all(records)
        return len(records)

    def add_alert(self, alert: "Alert") -> "Alert":
        """Persist one alert and return it with its database id."""
        with self.session_scope() as session:
            session.add(alert)
            session.flush()
            session.refresh(alert)
            return alert

    def get_recent_logs(self, limit: int = 500) -> list["LogRecord"]:
        """Return the newest log records."""
        from models.log_model import LogRecord

        with self.session_scope() as session:
            return list(
                session.query(LogRecord)
                .order_by(desc(LogRecord.timestamp))
                .limit(limit)
                .all()
            )

    def get_recent_alerts(self, limit: int = 100) -> list["Alert"]:
        """Return the newest alerts."""
        from models.alert_model import Alert

        with self.session_scope() as session:
            return list(
                session.query(Alert)
                .order_by(desc(Alert.timestamp))
                .limit(limit)
                .all()
            )

    def enforce_retention(self, retention_days: int = 30) -> int:
        """Delete logs older than the configured retention period."""
        from models.log_model import LogRecord

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        with self.session_scope() as session:
            deleted = (
                session.query(LogRecord)
                .filter(LogRecord.timestamp < cutoff)
                .delete(synchronize_session=False)
            )
        return int(deleted)


def init_db() -> DatabaseManager:
    """Initialize and return the default database manager."""
    manager = DatabaseManager()
    manager.initialize()
    return manager
