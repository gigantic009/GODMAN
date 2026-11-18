"""Explicit, allow-listed local tools. No arbitrary shell execution exists here."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .security import ApprovalRequired, AuditLog, SecurityPolicy


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    risk: str
    handler: Callable[..., Any]


class ToolRegistry:
    def __init__(self, policy: SecurityPolicy, audit: AuditLog):
        self.policy = policy
        self.audit = audit
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def describe(self) -> list[dict[str, str]]:
        return [
            {"name": t.name, "description": t.description, "risk": t.risk}
            for t in self._tools.values()
        ]

    def execute(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        if name not in self._tools:
            raise KeyError(f"Tool is not allow-listed: {name}")
        args = arguments or {}
        tool = self._tools[name]
        try:
            self.policy.authorize(name, args, risk=tool.risk)
            result = tool.handler(**args)
            self.audit.record(name, tool.risk, "success", "Completed")
            return result
        except ApprovalRequired as exc:
            self.audit.record(name, tool.risk, "denied", str(exc))
            raise
        except Exception as exc:
            self.audit.record(name, tool.risk, "error", type(exc).__name__)
            raise


def system_summary() -> dict[str, str]:
    return {
        "os": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "processor": platform.processor() or "Unknown",
    }


def disk_summary(path: str = ".") -> dict[str, int | str]:
    usage = shutil.disk_usage(path)
    return {
        "path": str(Path(path).resolve()),
        "total_gb": round(usage.total / (1024 ** 3), 2),
        "used_gb": round(usage.used / (1024 ** 3), 2),
        "free_gb": round(usage.free / (1024 ** 3), 2),
    }


def list_workspace_files(workspace: str, relative_path: str = ".") -> list[str]:
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Path escapes the configured workspace.")
    if not target.exists():
        raise FileNotFoundError(relative_path)
    if not target.is_dir():
        raise NotADirectoryError(relative_path)
    return sorted(p.name + ("/" if p.is_dir() else "") for p in target.iterdir())[:200]


def read_workspace_file(workspace: str, relative_path: str, max_chars: int = 12000) -> str:
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Path escapes the configured workspace.")
    if not target.is_file():
        raise FileNotFoundError(relative_path)
    if target.stat().st_size > 1_000_000:
        raise ValueError("File exceeds the 1 MB read limit.")
    return target.read_text(encoding="utf-8", errors="replace")[:max(1, min(max_chars, 12000))]


def create_workspace_file(workspace: str, relative_path: str, content: str) -> str:
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Path escapes the configured workspace.")
    if target.exists():
        raise FileExistsError("Refusing to overwrite an existing file.")
    if len(content) > 200_000:
        raise ValueError("Content exceeds the 200 KB write limit.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return str(target)


def open_allowlisted_app(app_name: str) -> str:
    """Launch a small named application allow-list; never accepts raw commands."""
    commands = {
        "notepad": ["notepad.exe"],
        "calculator": ["calc.exe"],
        "paint": ["mspaint.exe"],
        "vscode": ["code"],
    }
    key = app_name.strip().lower()
    if key not in commands:
        raise ValueError(f"App is not allow-listed. Choose: {', '.join(commands)}")
    if platform.system() != "Windows" and key != "vscode":
        raise OSError("This app launcher currently supports Windows.")
    subprocess.Popen(commands[key], shell=False, close_fds=True)
    return f"Launched {key}."


def build_default_registry(
    data_dir: str | Path,
    workspace: str | Path,
    policy: SecurityPolicy | None = None,
) -> ToolRegistry:
    data_dir = Path(data_dir)
    audit = AuditLog(data_dir / "audit.sqlite3")
    registry = ToolRegistry(policy or SecurityPolicy(), audit)
    registry.register(Tool("system_summary", "Read basic operating-system and Python information.", "read", system_summary))
    registry.register(Tool("disk_summary", "Read disk capacity for a path.", "read", disk_summary))
    registry.register(Tool("list_workspace_files", "List entries inside the configured workspace.", "read",
                           lambda relative_path=".": list_workspace_files(str(workspace), relative_path)))
    registry.register(Tool("read_workspace_file", "Read a UTF-8 file inside the configured workspace.", "read",
                           lambda relative_path, max_chars=12000: read_workspace_file(str(workspace), relative_path, max_chars)))
    registry.register(Tool("create_workspace_file", "Create a new file inside the workspace; never overwrites.", "write",
                           lambda relative_path, content: create_workspace_file(str(workspace), relative_path, content)))
    registry.register(Tool("open_app", "Launch one of the explicitly allow-listed desktop apps.", "system", open_allowlisted_app))
    return registry
