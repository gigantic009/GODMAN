"""Opt-in, workspace-scoped Microsoft Defender scanning.

The scanner delegates to the installed Defender engine. It never opens, executes,
uploads, quarantines, or deletes the target itself. Invocation is a system-risk
operation and must pass GODMAN's explicit approval policy.
"""
from __future__ import annotations

import platform
import subprocess
from pathlib import Path


def _defender_cli() -> Path:
    roots = [
        Path(r"C:\ProgramData\Microsoft\Windows Defender\Platform"),
        Path(r"C:\Program Files\Windows Defender"),
    ]
    candidates: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        if root.name == "Platform":
            try:
                candidates.extend(p / "MpCmdRun.exe" for p in root.iterdir()
                                  if p.is_dir() and (p / "MpCmdRun.exe").is_file())
            except OSError:
                continue
        else:
            candidate = root / "MpCmdRun.exe"
            if candidate.is_file():
                candidates.append(candidate)
    if not candidates:
        raise FileNotFoundError("Microsoft Defender command-line scanner was not found.")
    return sorted(candidates, key=lambda p: str(p.parent), reverse=True)[0]


def scan_with_microsoft_defender(workspace: str | Path, relative_path: str,
                                 timeout_seconds: int = 1800) -> dict:
    """Run a Defender custom scan on one file/folder inside the configured workspace."""
    if platform.system() != "Windows":
        raise OSError("Microsoft Defender scanning is supported here only on Windows.")
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target == root or root not in target.parents:
        raise ValueError("Choose a file or subfolder inside the configured workspace.")
    if not target.exists():
        raise FileNotFoundError(relative_path)
    if not (target.is_file() or target.is_dir()):
        raise ValueError("Target must be a regular file or directory.")
    scanner = _defender_cli()
    timeout = max(30, min(int(timeout_seconds), 1800))
    try:
        completed = subprocess.run(
            [str(scanner), "-Scan", "-ScanType", "3", "-File", str(target)],
            capture_output=True, text=True, timeout=timeout, check=False, shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Microsoft Defender scan exceeded its time limit.") from exc
    if completed.returncode != 0:
        raise RuntimeError(
            "Microsoft Defender reported a scan error. Check Defender status and Windows permissions."
        )
    return {
        "engine": "Microsoft Defender",
        "target_type": "directory" if target.is_dir() else "file",
        "scan": "completed",
        "exit_code": completed.returncode,
        "target": str(target),
        "limitations": [
            "A successful scan does not prove the target is malware-free.",
            "Detection depends on Defender configuration, signatures, cloud protection, and scan coverage.",
            "This custom scan does not guarantee remediation or quarantine of every detection.",
            "The scan is limited to the selected workspace file or subfolder; it is not a whole-device scan.",
        ],
    }
