"""Local persistent memory using only Python's SQLite standard library."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class MemoryStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'note',
                    content TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_created ON memories(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_conversation_created ON conversation(created_at)")

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def remember(self, content: str, category: str = "note") -> int:
        value = content.strip()
        if not value:
            raise ValueError("Memory cannot be empty.")
        if len(value) > 4000:
            raise ValueError("Memory is too long (maximum 4,000 characters).")
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO memories(created_at, category, content) VALUES (?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), category[:40], value),
            )
            return int(cursor.lastrowid)

    def search(self, query: str, limit: int = 10) -> list[dict]:
        term = query.strip()
        if not term:
            return self.recent(limit)
        # Escape LIKE metacharacters so search is literal, not user-controlled SQL.
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, category, content FROM memories WHERE content LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ?",
                (f"%{escaped}%", max(1, min(limit, 50))),
            ).fetchall()
        return [dict(zip(("id", "created_at", "category", "content"), row)) for row in rows]

    def recent(self, limit: int = 10) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, category, content FROM memories ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 50)),),
            ).fetchall()
        return [dict(zip(("id", "created_at", "category", "content"), row)) for row in rows]

    def forget(self, memory_id: int) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
            return cursor.rowcount > 0

    def save_message(self, role: str, content: str) -> None:
        if role not in {"user", "assistant"} or not content.strip():
            return
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO conversation(created_at, role, content) VALUES (?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), role, content[:12000]),
            )

    def recent_conversation(self, limit: int = 20) -> list[dict[str, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT role, content FROM conversation ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [{"role": role, "content": content} for role, content in reversed(rows)]
