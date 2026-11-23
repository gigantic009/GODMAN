"""Normalized event model and bounded in-process event bus."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
import json
import uuid


def _validate_payload(value: Any, depth: int = 0) -> None:
    if depth > 6:
        raise ValueError("event payload nesting exceeds limit")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > 4096:
            raise ValueError("event string exceeds limit")
        return
    if isinstance(value, float):
        import math
        if not math.isfinite(value):
            raise ValueError("event numeric values must be finite")
        return
    if isinstance(value, list):
        if len(value) > 100:
            raise ValueError("event array exceeds limit")
        for item in value:
            _validate_payload(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 100:
            raise ValueError("event object exceeds limit")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("event object keys must be bounded strings")
            _validate_payload(item, depth + 1)
        return
    raise TypeError("event payload must contain JSON-compatible values only")


@dataclass(frozen=True)
class Event:
    event_type: str
    source: str
    data: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host_id: str | None = None
    schema_version: int = 1

    def __post_init__(self):
        if not isinstance(self.event_type, str) or not self.event_type.strip() or len(self.event_type) > 128:
            raise ValueError("event_type must be non-empty and bounded")
        if not isinstance(self.source, str) or not self.source.strip() or len(self.source) > 128:
            raise ValueError("source must be non-empty and bounded")
        if not isinstance(self.data, dict):
            raise TypeError("data must be a dictionary")
        _validate_payload(self.data)
        if len(json.dumps(self.data, ensure_ascii=False).encode("utf-8")) > 32768:
            raise ValueError("event payload exceeds 32 KB")
        if self.schema_version != 1:
            raise ValueError("unsupported event schema version")


class EventBus:
    """Synchronous fan-out with bounded history; subscriber errors are isolated."""

    def __init__(self, history_limit: int = 1000):
        if not isinstance(history_limit, int) or isinstance(history_limit, bool) or history_limit < 1:
            raise ValueError("history_limit must be positive")
        self.history_limit = history_limit
        self._history = []
        self._subscribers = []
        self.subscriber_errors = []

    def subscribe(self, callback: Callable[[Event], None]):
        if not callable(callback):
            raise TypeError("subscriber must be callable")
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def publish(self, event: Event) -> Event:
        if not isinstance(event, Event):
            raise TypeError("only normalized Event instances may be published")
        self._history.append(event)
        if len(self._history) > self.history_limit:
            self._history = self._history[-self.history_limit:]
        for callback in tuple(self._subscribers):
            try:
                callback(event)
            except Exception as exc:
                self.subscriber_errors.append(type(exc).__name__)
                if len(self.subscriber_errors) > 100:
                    self.subscriber_errors = self.subscriber_errors[-100:]
        return event

    def history(self, limit: int = 100) -> list[Event]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        return list(self._history[-max(1, min(limit, self.history_limit)):])
