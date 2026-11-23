"""Deterministic, testable event-to-finding detection rules."""
from dataclasses import dataclass
from typing import Any
from .events import Event
from .findings import Finding, Evidence


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    title: str
    event_type: str
    field_equals: dict[str, Any]
    severity: str = "medium"
    confidence: float = 0.7
    description: str = ""

    def __post_init__(self):
        if not all(isinstance(x, str) and x.strip() for x in (self.rule_id, self.title, self.event_type)):
            raise ValueError("rule identity fields required")
        if not isinstance(self.field_equals, dict) or len(self.field_equals) > 50:
            raise ValueError("invalid or excessive rule conditions")
        if self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("invalid severity")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not 0 <= self.confidence <= 1:
            raise ValueError("invalid confidence")


class DetectionEngine:
    def __init__(self, rules=()):
        self.rules = []
        self.findings = []
        for rule in rules:
            self.add_rule(rule)

    def add_rule(self, rule):
        if not isinstance(rule, DetectionRule):
            raise TypeError("rule must be a DetectionRule")
        if any(existing.rule_id == rule.rule_id for existing in self.rules):
            raise ValueError("duplicate rule ID")
        self.rules.append(rule)

    def process(self, event: Event) -> list[Finding]:
        if not isinstance(event, Event):
            raise TypeError("detection accepts normalized Event instances")
        findings = []
        for rule in self.rules:
            if rule.event_type != event.event_type:
                continue
            if all(event.data.get(key) == value for key, value in rule.field_equals.items()):
                evidence = Evidence(event_id=event.event_id,
                                   summary=f"Event matched detection rule {rule.rule_id}",
                                   source=event.source)
                findings.append(Finding(rule_id=rule.rule_id, title=rule.title,
                                       severity=rule.severity, confidence=rule.confidence,
                                       evidence=(evidence,), description=rule.description))
        self.findings.extend(findings)
        return findings

    def attach(self, bus):
        if not isinstance(bus, EventBus):
            raise TypeError("attach requires an EventBus")
        bus.subscribe(self._on_event)
        return self

    def _on_event(self, event):
        self.process(event)


from .events import EventBus
