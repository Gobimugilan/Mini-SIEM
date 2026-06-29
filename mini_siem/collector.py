"""Windows Event Log collector for Mini SIEM."""

from __future__ import annotations

import logging
import platform
import json
import subprocess
import sys
from argparse import ArgumentParser
from datetime import datetime, timezone
from typing import Iterable

from database import DatabaseManager, init_db
from models.log_model import LogRecord


LOGGER = logging.getLogger(__name__)


class EventLogAccessError(RuntimeError):
    """Raised when Windows Event Log collection cannot access the log."""


class WindowsEventCollector:
    """Collect selected Windows Security events using pywin32."""

    SUPPORTED_EVENT_IDS = {4624, 4625, 4720, 4726, 4740}

    def __init__(self, server: str = "localhost", log_type: str = "Security") -> None:
        self.server = server
        self.log_type = log_type

    @staticmethod
    def _load_pywin32_modules() -> tuple[object, object, object, object, object]:
        """Import pywin32 modules only when collection is requested."""
        try:
            import win32api
            import win32con
            import win32evtlog
            import win32evtlogutil
            import win32security
        except ImportError as exc:
            raise RuntimeError(
                "pywin32 is required for Windows Event Log collection. "
                "Install requirements.txt on Windows and retry."
            ) from exc
        return win32api, win32con, win32evtlog, win32evtlogutil, win32security

    @staticmethod
    def _enable_security_privilege(
        win32api: object,
        win32con: object,
        win32security: object,
    ) -> None:
        """Enable the Windows privilege required to read Security event logs."""
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
            )
            privilege_id = win32security.LookupPrivilegeValue(
                None,
                "SeSecurityPrivilege",
            )
            win32security.AdjustTokenPrivileges(
                token,
                False,
                [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)],
            )
        except Exception as exc:
            raise EventLogAccessError(
                "Could not enable SeSecurityPrivilege. Start Command Prompt "
                "with Run as administrator, then launch Streamlit from that "
                "same window."
            ) from exc

        last_error = win32api.GetLastError()
        if last_error:
            raise EventLogAccessError(
                "The current Windows token does not have SeSecurityPrivilege. "
                "Open an elevated terminal, or grant this user 'Manage auditing "
                "and security log' in Local Security Policy."
            )

    @staticmethod
    def _normalize_event_id(event_id: int) -> int:
        """Strip qualifier bits from Windows event ids."""
        return int(event_id) & 0xFFFF

    @staticmethod
    def _normalize_timestamp(raw_timestamp: object) -> datetime:
        """Convert pywin32 timestamps into timezone-aware datetimes."""
        if isinstance(raw_timestamp, datetime):
            if raw_timestamp.tzinfo is None:
                return raw_timestamp.replace(tzinfo=timezone.utc)
            return raw_timestamp.astimezone(timezone.utc)
        return datetime.now(timezone.utc)

    @staticmethod
    def _extract_username(event_id: int, inserts: Iterable[object] | None) -> str:
        """Best-effort username extraction from Windows Security event fields."""
        values = [str(item) for item in inserts or [] if item is not None]
        if not values:
            return "Unknown"

        field_map = {
            4624: 5,
            4625: 5,
            4720: 0,
            4726: 0,
            4740: 0,
        }
        index = field_map.get(event_id)
        if index is not None and index < len(values):
            return values[index] or "Unknown"

        for value in values:
            if value and value != "-":
                return value
        return "Unknown"

    def _collect_with_get_win_event(self, limit: int = 100) -> list[LogRecord]:
        """Collect Security events through PowerShell's modern Get-WinEvent API."""
        event_ids = ",".join(str(event_id) for event_id in sorted(self.SUPPORTED_EVENT_IDS))
        script = f"""
$events = Get-WinEvent -FilterHashtable @{{LogName='{self.log_type}'; Id={event_ids}}} -MaxEvents {int(limit)} -ErrorAction Stop
$events | ForEach-Object {{
    [PSCustomObject]@{{
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
        Id = $_.Id
        MachineName = $_.MachineName
        Message = $_.Message
        Properties = @($_.Properties | ForEach-Object {{
            if ($null -eq $_.Value) {{ "" }} else {{ [string]$_.Value }}
        }})
    }}
}} | ConvertTo-Json -Depth 4
"""
        try:
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.CalledProcessError as exc:
            details = (exc.stderr or exc.stdout or str(exc)).strip()
            raise EventLogAccessError(
                "Get-WinEvent could not read Windows Security logs. "
                f"Details: {details}"
            ) from exc
        except FileNotFoundError as exc:
            raise EventLogAccessError(
                "powershell.exe was not found, so the Windows log fallback could "
                "not run."
            ) from exc

        output = completed.stdout.strip()
        if not output:
            return []

        try:
            raw_events = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Get-WinEvent returned output that could not be parsed as JSON."
            ) from exc

        if isinstance(raw_events, dict):
            raw_events = [raw_events]

        records: list[LogRecord] = []
        for raw_event in raw_events:
            event_id = self._normalize_event_id(int(raw_event["Id"]))
            properties = raw_event.get("Properties") or []
            timestamp_raw = str(raw_event.get("TimeCreated") or "")
            try:
                timestamp = datetime.fromisoformat(timestamp_raw)
            except ValueError:
                timestamp = datetime.now(timezone.utc)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            else:
                timestamp = timestamp.astimezone(timezone.utc)

            records.append(
                LogRecord(
                    timestamp=timestamp,
                    event_id=event_id,
                    username=self._extract_username(event_id, properties),
                    computer_name=str(raw_event.get("MachineName") or "Unknown"),
                    message=str(raw_event.get("Message") or "").strip(),
                )
            )

        return records

    def collect(self, limit: int = 100) -> list[LogRecord]:
        """Collect recent supported Windows Security events."""
        if platform.system().lower() != "windows":
            LOGGER.warning("Windows Event Log collection is only available on Windows.")
            return []

        (
            win32api,
            win32con,
            win32evtlog,
            win32evtlogutil,
            win32security,
        ) = self._load_pywin32_modules()
        self._enable_security_privilege(win32api, win32con, win32security)
        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        handle = None
        try:
            handle = win32evtlog.OpenEventLog(self.server, self.log_type)
        except Exception as exc:
            LOGGER.warning(
                "pywin32 Event Log open failed (%s); retrying with Get-WinEvent.",
                exc,
            )
            return self._collect_with_get_win_event(limit=limit)
        records: list[LogRecord] = []

        try:
            while len(records) < limit:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break

                for event in events:
                    event_id = self._normalize_event_id(event.EventID)
                    if event_id not in self.SUPPORTED_EVENT_IDS:
                        continue

                    try:
                        message = win32evtlogutil.SafeFormatMessage(
                            event,
                            self.log_type,
                        )
                    except Exception as exc:
                        LOGGER.debug("Could not format event message: %s", exc)
                        message = "\n".join(
                            str(item) for item in event.StringInserts or []
                        )

                    records.append(
                        LogRecord(
                            timestamp=self._normalize_timestamp(event.TimeGenerated),
                            event_id=event_id,
                            username=self._extract_username(
                                event_id,
                                event.StringInserts,
                            ),
                            computer_name=str(event.ComputerName or "Unknown"),
                            message=message.strip(),
                        )
                    )

                    if len(records) >= limit:
                        break
        except Exception as exc:
            LOGGER.warning(
                "pywin32 Event Log read failed (%s); retrying with Get-WinEvent.",
                exc,
            )
            return self._collect_with_get_win_event(limit=limit)
        finally:
            if handle is not None:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception as exc:
                    LOGGER.debug("Could not close Event Log handle: %s", exc)

        return records

    def collect_and_store(
        self,
        db: DatabaseManager,
        limit: int = 100,
        skip_duplicates: bool = True,
    ) -> int:
        """Collect events and store them in SQLite."""
        records = self.collect(limit=limit)
        if not records:
            return 0

        if not skip_duplicates:
            return db.add_logs(records)

        inserted = 0
        with db.session_scope() as session:
            for record in records:
                exists = (
                    session.query(LogRecord)
                    .filter(LogRecord.timestamp == record.timestamp)
                    .filter(LogRecord.event_id == record.event_id)
                    .filter(LogRecord.username == record.username)
                    .filter(LogRecord.computer_name == record.computer_name)
                    .filter(LogRecord.message == record.message)
                    .first()
                )
                if exists:
                    continue
                session.add(record)
                inserted += 1

        return inserted


def is_running_as_admin() -> bool:
    """Return True when the current process has administrator elevation."""
    if platform.system().lower() != "windows":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def diagnose_access() -> int:
    """Print Windows Security log access diagnostics."""
    print(f"Windows: {platform.system().lower() == 'windows'}")
    print(f"Administrator: {is_running_as_admin()}")

    if platform.system().lower() != "windows":
        print("Security Event Log collection is only available on Windows.")
        return 1

    try:
        collector = WindowsEventCollector()
        collector.collect(limit=1)
    except EventLogAccessError as exc:
        print(f"Security log access: FAILED - {exc}")
        print("\nFix:")
        print("1. Close this terminal.")
        print("2. Open Command Prompt with 'Run as administrator'.")
        print('3. cd "C:\\final year project\\mini siem\\mini_siem"')
        print("4. .\\venv\\Scripts\\activate")
        print("5. python collector.py --diagnose")
        print(
            "\nIf it still fails, open Local Security Policy > Local Policies > "
            "User Rights Assignment > Manage auditing and security log, then "
            "add your Windows user and sign out/sign in."
        )
        return 1

    print("Security log access: OK")
    return 0


def seed_sample_logs(db: DatabaseManager) -> int:
    """Insert realistic sample logs for dashboard demos without Windows access."""
    sample_time = datetime.now(timezone.utc)
    sample_logs = [
        LogRecord(
            timestamp=sample_time,
            event_id=4625,
            username="alice",
            computer_name="WIN-LAB-01",
            message="An account failed to log on. Failure reason: bad password.",
        ),
        LogRecord(
            timestamp=sample_time,
            event_id=4625,
            username="alice",
            computer_name="WIN-LAB-01",
            message="An account failed to log on. Failure reason: bad password.",
        ),
        LogRecord(
            timestamp=sample_time,
            event_id=4625,
            username="alice",
            computer_name="WIN-LAB-01",
            message="An account failed to log on. Failure reason: bad password.",
        ),
        LogRecord(
            timestamp=sample_time,
            event_id=4625,
            username="alice",
            computer_name="WIN-LAB-01",
            message="An account failed to log on. Failure reason: bad password.",
        ),
        LogRecord(
            timestamp=sample_time,
            event_id=4625,
            username="alice",
            computer_name="WIN-LAB-01",
            message="An account failed to log on. Failure reason: bad password.",
        ),
        LogRecord(
            timestamp=sample_time,
            event_id=4625,
            username="alice",
            computer_name="WIN-LAB-01",
            message="An account failed to log on. Failure reason: bad password.",
        ),
        LogRecord(
            timestamp=sample_time,
            event_id=4720,
            username="administrator",
            computer_name="WIN-LAB-01",
            message="A user account was created. Target account: temp_support.",
        ),
        LogRecord(
            timestamp=sample_time,
            event_id=4740,
            username="alice",
            computer_name="WIN-LAB-01",
            message="A user account was locked out.",
        ),
    ]
    return db.add_logs(sample_logs)


def build_parser() -> ArgumentParser:
    """Build command-line arguments for the collector."""
    parser = ArgumentParser(description="Mini SIEM Windows Event Log collector")
    parser.add_argument("--limit", type=int, default=250, help="Maximum logs to read")
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Check whether Security log access is available",
    )
    parser.add_argument(
        "--seed-sample",
        action="store_true",
        help="Insert sample logs for dashboard demonstration",
    )
    return parser


def main() -> int:
    """CLI entry point for manual collection."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = build_parser().parse_args()

    if args.diagnose:
        return diagnose_access()

    db = init_db()
    if args.seed_sample:
        inserted = seed_sample_logs(db)
        LOGGER.info("Inserted %s sample log records.", inserted)
        return 0

    collector = WindowsEventCollector()
    try:
        inserted = collector.collect_and_store(db, limit=args.limit)
    except EventLogAccessError as exc:
        LOGGER.error("%s", exc)
        LOGGER.error("Run 'python collector.py --diagnose' for exact steps.")
        return 1

    LOGGER.info("Inserted %s new log records.", inserted)
    return 0


if __name__ == "__main__":
    sys.exit(main())
