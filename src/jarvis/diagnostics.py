"""Read-only system diagnostics for Phase 2."""
from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path


def collect_diagnostics() -> dict:
    """Collect lightweight, read-only diagnostics without enumerating private files."""
    home = Path.home()
    drives = []
    candidates = [Path.home().anchor or str(home)]
    if os.name == "nt":
        candidates = [f"{letter}:\\" for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ"]
    for candidate in candidates:
        if Path(candidate).exists():
            try:
                usage = shutil.disk_usage(candidate)
                drives.append({
                    "path": candidate,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                })
            except OSError:
                continue
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "home_directory_exists": home.exists(),
        "drives": drives,
    }
