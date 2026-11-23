"""Bounded local SQLite evidence/event store. Data is stored locally only."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class LocalKnowledgeStore:
    """Small append-only local store with bounded retention and no network behavior."""

    def __init__(self, path: str | Path, retention: int = 10000):
        if isinstance(retention, bool) or not isinstance(retention, int) or retention < 100:
            raise ValueError("retention must be an integer >= 100")
        self.path = Path(path)
        self.retention = retention
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, observed_at TEXT NOT NULL,
                event_type TEXT NOT NULL, source TEXT NOT NULL, payload TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                rule_id TEXT NOT NULL, severity TEXT NOT NULL,
                confidence REAL NOT NULL, payload TEXT NOT NULL)""")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA busy_timeout=5000")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def save_event(self, event):
        from .events import Event
        if not isinstance(event, Event):
            raise TypeError("expected normalized Event")
        payload = json.dumps(event.data, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as db:
            db.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?)",
                       (event.event_id, event.timestamp, event.event_type, event.source, payload))
            db.execute("DELETE FROM events WHERE event_id IN (SELECT event_id FROM events ORDER BY observed_at DESC, event_id DESC LIMIT -1 OFFSET ?)", (self.retention,))

    def save_finding(self, finding):
        from .findings import Finding
        if not isinstance(finding, Finding):
            raise TypeError("expected evidence-linked Finding")
        payload = json.dumps({
            "title": finding.title, "description": finding.description,
            "status": finding.status,
            "evidence": [vars(item) for item in finding.evidence],
        }, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as db:
            db.execute("INSERT OR IGNORE INTO findings VALUES (?, ?, ?, ?, ?, ?)",
                       (finding.finding_id, finding.created_at, finding.rule_id,
                        finding.severity, finding.confidence, payload))
            db.execute("DELETE FROM findings WHERE finding_id IN (SELECT finding_id FROM findings ORDER BY created_at DESC, finding_id DESC LIMIT -1 OFFSET ?)", (self.retention,))

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = self._limit(limit)
        with self._connect() as db:
            rows = db.execute("SELECT event_id,observed_at,event_type,source,payload FROM events ORDER BY observed_at DESC, event_id DESC LIMIT ?", (limit,)).fetchall()
        return [{"event_id": row[0], "timestamp": row[1], "event_type": row[2],
                 "source": row[3], "data": json.loads(row[4])} for row in rows]

    def recent_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = self._limit(limit)
        with self._connect() as db:
            rows = db.execute("SELECT finding_id,created_at,rule_id,severity,confidence,payload FROM findings ORDER BY created_at DESC, finding_id DESC LIMIT ?", (limit,)).fetchall()
        return [{"finding_id": row[0], "created_at": row[1], "rule_id": row[2],
                 "severity": row[3], "confidence": row[4], **json.loads(row[5])} for row in rows]

    @staticmethod
    def _limit(limit):
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        return max(1, min(limit, 500))
