"""Deterministic, testable event-to-finding detection rules."""
from dataclasses import dataclass
import json
from typing import Any
from .events import Event, EventBus, _validate_payload
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
        if not all(isinstance(x, str) and x.strip() and len(x) <= 128 for x in
                   (self.rule_id, self.title, self.event_type)):
            raise ValueError("rule identity fields must be non-empty and bounded")
        if not isinstance(self.field_equals, dict) or len(self.field_equals) > 50:
            raise ValueError("invalid or excessive rule conditions")
        for key in self.field_equals:
            if not isinstance(key, str) or not key.strip() or len(key) > 128:
                raise ValueError("condition keys must be bounded strings")
        _validate_payload(self.field_equals)
        if len(json.dumps(self.field_equals, ensure_ascii=False).encode("utf-8")) > 8192:
            raise ValueError("rule conditions exceed 8 KB")
        if self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("invalid severity")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not 0 <= self.confidence <= 1:
            raise ValueError("invalid confidence")
        if not isinstance(self.description, str) or len(self.description) > 2000:
            raise ValueError("description must be bounded")


class DetectionEngine:
    def __init__(self, rules=(), store=None, max_findings: int = 1000):
        if isinstance(max_findings, bool) or not isinstance(max_findings, int) or not 1 <= max_findings <= 10000:
            raise ValueError("max_findings must be between 1 and 10000")
        self.rules = []
        self.findings = []
        self.store = store
        self.max_findings = max_findings
        for rule in rules:
            self.add_rule(rule)

    def add_rule(self, rule):
        if not isinstance(rule, DetectionRule):
            raise TypeError("rule must be a DetectionRule")
        if len(self.rules) >= 500:
            raise ValueError("detection rule limit reached")
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
        if len(self.findings) > self.max_findings:
            self.findings = self.findings[-self.max_findings:]
        if self.store is not None:
            for finding in findings:
                self.store.save_finding(finding)
        return findings

    def attach(self, bus):
        if not isinstance(bus, EventBus):
            raise TypeError("attach requires an EventBus")
        bus.subscribe(self._on_event)
        return self

    def _on_event(self, event):
        if self.store is not None:
            self.store.save_event(event)
        self.process(event)
