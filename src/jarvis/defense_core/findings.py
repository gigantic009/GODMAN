"""Evidence-linked defensive findings; conclusions remain explainable."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid


def _bounded_text(value, label, maximum=128):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must be non-empty and bounded")


@dataclass(frozen=True)
class Evidence:
    event_id: str
    summary: str
    source: str
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        _bounded_text(self.event_id, "event_id")
        _bounded_text(self.summary, "summary", 1000)
        _bounded_text(self.source, "source")
        _bounded_text(self.observed_at, "observed_at", 64)
        try:
            parsed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("observed_at must be ISO-8601") from exc
        if parsed.tzinfo is None:
            raise ValueError("observed_at must include a timezone")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: float
    evidence: tuple[Evidence, ...]
    description: str = ""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "open"

    def __post_init__(self):
        _bounded_text(self.rule_id, "rule_id")
        _bounded_text(self.title, "title", 256)
        _bounded_text(self.finding_id, "finding_id")
        _bounded_text(self.created_at, "created_at", 64)
        if not isinstance(self.description, str) or len(self.description) > 2000:
            raise ValueError("description must be a bounded string")
        if self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("invalid severity")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if not isinstance(self.evidence, tuple) or not 1 <= len(self.evidence) <= 50:
            raise ValueError("findings require 1-50 evidence records in a tuple")
        if any(not isinstance(item, Evidence) for item in self.evidence):
            raise TypeError("finding evidence must contain Evidence objects")
        if self.status not in {"open", "acknowledged", "resolved", "false_positive"}:
            raise ValueError("invalid status")
