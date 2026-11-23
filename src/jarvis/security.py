"""Permission checks and append-only audit events for local tools."""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ApprovalRequired(PermissionError):
    """Raised when an action needs explicit user approval."""


class SecurityPolicy:
    """Small explicit policy; never infer permission from an LLM request."""

    def __init__(self, approval_callback=None):
        self.approval_callback = approval_callback or self._console_approval

    @staticmethod
    def _console_approval(tool_name: str, arguments: dict[str, Any]) -> bool:
        print(f"\nGODMAN wants to run: {tool_name}")
        print(f"Arguments: {json.dumps(arguments, ensure_ascii=False, indent=2)}")
        answer = input("Approve this action? Type YES: ").strip()
        return answer == "YES"

    def authorize(self, tool_name: str, arguments: dict[str, Any], *, risk: str) -> None:
        if risk == "read":
            return
        if risk not in {"write", "external", "system"}:
            raise ValueError(f"Unknown risk class: {risk}")
        if not self.approval_callback(tool_name, arguments):
            raise ApprovalRequired(f"User declined action: {tool_name}")


class AuditLog:
    """SQLite-backed audit log. Arguments are redacted by callers before logging."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tool_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details TEXT NOT NULL
                )
            """)

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @staticmethod
    def _redact(details: str) -> str:
        # Keep audit entries useful while reducing accidental secret leakage.
        text = str(details)
        patterns = [
            (r"(?i)(api[_-]?key|token|password|secret|authorization)\\s*[:=]\\s*[^\\s,;]+", r"\\1=[REDACTED]"),
            (r"(?i)bearer\\s+[a-z0-9._~+/-]+=*", "Bearer [REDACTED]"),
            (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", "[EMAIL]"),
        ]
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text)
        return text[:2000]

    def record(self, tool_name: str, risk: str, outcome: str, details: str = "") -> None:
        details = self._redact(details)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO tool_audit(created_at, tool_name, risk, outcome, details) VALUES (?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), tool_name, risk, outcome, details[:2000]),
            )

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, tool_name, risk, outcome, details FROM tool_audit ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        keys = ("id", "created_at", "tool_name", "risk", "outcome", "details")
        return [dict(zip(keys, row)) for row in rows]
