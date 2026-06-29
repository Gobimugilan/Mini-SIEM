"""Build the Mini SIEM Windows executable with PyInstaller."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APP_FILES = [
    "app.py",
    "dashboard.py",
    "collector.py",
    "database.py",
    "detection_engine.py",
    "ai_analyzer.py",
]
APP_DIRS = ["models", "rules"]
EXCLUDED_MODULES = [
    "cv2",
    "google",
    "grpc",
    "langchain",
    "langcodes",
    "matplotlib",
    "scipy",
    "sklearn",
    "spacy",
    "tensorflow",
    "thinc",
    "torch",
    "transformers",
]


def add_data_arg(path: str) -> str:
    """Return a PyInstaller --add-data value for Windows."""
    return f"{ROOT / path};{path}"


def ensure_pyinstaller() -> None:
    """Install PyInstaller when it is not already available."""
    if shutil.which("pyinstaller"):
        return
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "pyinstaller"],
        cwd=ROOT,
    )


def build() -> None:
    """Run PyInstaller with Streamlit-friendly collection options."""
    ensure_pyinstaller()

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--name",
        "MiniSIEM",
        "--collect-data",
        "streamlit",
        "--collect-data",
        "plotly",
        "--copy-metadata",
        "streamlit",
        "--copy-metadata",
        "plotly",
        "--copy-metadata",
        "pandas",
        "--hidden-import",
        "win32timezone",
    ]

    for module_name in EXCLUDED_MODULES:
        command.extend(["--exclude-module", module_name])

    for file_name in APP_FILES:
        command.extend(["--add-data", add_data_arg(file_name)])
    for dir_name in APP_DIRS:
        command.extend(["--add-data", add_data_arg(dir_name)])

    command.append(str(ROOT / "mini_siem_launcher.py"))
    subprocess.check_call(command, cwd=ROOT)

    exe_path = ROOT / "dist" / "MiniSIEM" / "MiniSIEM.exe"
    print(f"\nBuilt executable: {exe_path}")
    print("Run it from an Administrator terminal if Windows Security log collection is needed.")


if __name__ == "__main__":
    build()
