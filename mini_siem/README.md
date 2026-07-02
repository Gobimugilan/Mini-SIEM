# AI-Powered Mini SIEM for Windows Security Monitoring

This project is a Python-based SOC Mini SIEM that collects Windows Security Event Logs, stores normalized events in SQLite, detects common account-security incidents, optionally enriches alerts with Ollama/Qwen analysis, and displays everything in a Streamlit dashboard.

## Features

- Windows Security Event Log collection with `pywin32`
- SQLite persistence with SQLAlchemy ORM
- Rule engine for failed logins, brute force attempts, account creation, account lockout, removable media indicators, and IOC matching
- Alert deduplication and log retention
- Optional Ollama AI analyst enrichment
- Streamlit dashboard with metrics, Plotly charts, searchable logs, alert tables, and AI response guidance

## Architecture Diagram

```text
Windows Security Logs
        |
        v
 collector.py
        |
        v
 SQLite logs table <---- dashboard.py / app.py
        |
        v
 detection_engine.py ---- rules/*
        |
        v
 SQLite alerts table
        |
        v
 ai_analyzer.py ---- Ollama Qwen model (optional)
```

## Project Structure

```text
mini_siem/
|-- app.py
|-- collector.py
|-- database.py
|-- detection_engine.py
|-- dashboard.py
|-- ai_analyzer.py
|-- models/
|   |-- log_model.py
|   `-- alert_model.py
|-- rules/
|   |-- failed_login.py
|   |-- brute_force.py
|   |-- user_creation.py
|   `-- usb_monitor.py
|-- data/
|   `-- logs.db
|-- requirements.txt
`-- README.md
```

## Installation

Use Python 3.12 or newer on Windows.

```powershell
cd "C:\final year project\mini siem\mini_siem"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Windows Security log collection may require running PowerShell, Command Prompt, or your IDE as Administrator.

Check Security log permissions:

```powershell
python collector.py --diagnose
```

If `Administrator` is `False`, close the terminal and open Command Prompt with `Run as administrator`.

If Administrator is `True` but access still fails, grant your Windows user this right:

```text
Local Security Policy > Local Policies > User Rights Assignment > Manage auditing and security log
```

After changing that policy, sign out and sign back in.

## Optional Ollama Setup

Install Ollama, start it, and pull a Qwen model:

```powershell
ollama pull qwen2.5:latest
```

In the dashboard sidebar, enable `Use Ollama AI analysis` before running the detection engine.

## Usage

Start the Streamlit app:

```powershell
cd "C:\final year project\mini siem\mini_siem"
streamlit run app.py
```

From the dashboard sidebar:

1. Click `Collect Windows Logs`.
2. Click `Run Detection Engine`.
3. Review metrics, charts, alerts, searchable logs, and AI analysis.

You can also run collection and detection from the command line:

```powershell
python collector.py
python detection_engine.py
```

For a demo without Windows Security log permissions, load sample logs:

```powershell
python collector.py --seed-sample
python detection_engine.py
```

The dashboard also has a `Load Sample Logs` button in the sidebar.

## Build Windows Executable

Build a double-clickable Windows executable with PyInstaller:

```powershell
cd "C:\final year project\mini siem\mini_siem"
python build_executable.py
```

After the build completes, run:

```text
dist\MiniSIEM\MiniSIEM.exe
```

For Windows Security log collection, start the EXE from an Administrator terminal:

```powershell
cd "C:\final year project\mini siem\mini_siem\dist\MiniSIEM"
.\MiniSIEM.exe
```

The executable stores its SQLite database in `dist\MiniSIEM\data\logs.db`.

## Detection Rules

- `4625` Failed Login Detection: creates a Low alert.
- More than five `4625` events within five minutes for the same user: creates a High brute force alert.
- `4720` New User Detection: creates a Medium alert.
- `4740` Account Lockout: creates a High alert.
- IOC matching: creates a Critical alert when known suspicious strings appear in username, host, or message fields.

## Database Schema

### logs

- `id`
- `timestamp`
- `event_id`
- `username`
- `computer_name`
- `message`

### alerts

- `id`
- `timestamp`
- `severity`
- `title`
- `description`
- `event_id`
- `related_log_id`
- `fingerprint`
- `ai_summary`
- `ai_severity_assessment`
- `ai_investigation_steps`
- `ai_mitre_mapping`
- `ai_recommended_remediation`


## Notes

- The database is created automatically at `data/logs.db`.
- On non-Windows systems, the dashboard still runs, but Windows Event Log collection returns no records.
- Ollama integration is optional. If Ollama is disabled or unavailable, deterministic analyst guidance is stored for generated alerts.
