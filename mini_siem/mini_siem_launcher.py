"""Executable launcher for the Mini SIEM Streamlit dashboard."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def bundled_path(relative_path: str) -> Path:
    """Return a path inside the PyInstaller bundle or source directory."""
    base_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base_dir / relative_path


def main() -> None:
    """Start the Streamlit dashboard from an executable bundle."""
    app_path = bundled_path("app.py")
    if not app_path.exists():
        raise FileNotFoundError(f"Could not find bundled Streamlit app: {app_path}")

    os.environ.setdefault("STREAMLIT_BROWSER_GATHER_USAGE_STATS", "false")
    os.environ.setdefault("STREAMLIT_SERVER_HEADLESS", "false")

    sys.argv = [
        "streamlit",
        "run",
        str(app_path),
        "--server.headless",
        "false",
        "--server.port",
        "8501",
    ]

    from streamlit.web.cli import main as streamlit_main

    streamlit_main()


if __name__ == "__main__":
    main()
