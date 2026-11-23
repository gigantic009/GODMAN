import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.defense_core import Event, EventBus, Evidence, Finding, ActionPolicy, DetectionRule, DetectionEngine


class DefensiveCoreTests(unittest.TestCase):
    def test_event_validation_and_bounded_history(self):
        bus = EventBus(2)
        events = [Event("proc.start", "test", {"pid": i}) for i in (1, 2, 3)]
        for event in events:
            bus.publish(event)
        self.assertEqual([e.data["pid"] for e in bus.history()], [2, 3])
        self.assertEqual(bus.history(0), [])
        with self.assertRaises(TypeError):
            bus.publish({})
        with self.assertRaises(ValueError):
            Event("x", "source", {}, timestamp="not-a-date")
        with self.assertRaises(ValueError):
            Event("x", "source", {}, schema_version=True)
        offset_event = Event("x", "source", {}, timestamp="2026-11-23T15:00:00+05:30")
        self.assertTrue(offset_event.timestamp.endswith("+00:00"))

    def test_event_payload_is_snapshotted(self):
        payload = {"nested": {"items": [1, 2]}}
        event = Event("x", "source", payload)
        payload["nested"]["items"].append(3)
        self.assertEqual(event.data["nested"]["items"], [1, 2])
        with self.assertRaises(TypeError):
            event.data["nested"]["items"].append(3)
        with self.assertRaises(TypeError):
            event.data["nested"]["new"] = "value"

    def test_subscriber_failure_is_isolated(self):
        bus = EventBus()
        seen = []
        bus.subscribe(lambda e: (_ for _ in ()).throw(RuntimeError()))
        bus.subscribe(lambda e: seen.append(e.event_id))
        event = Event("x", "source", {})
        bus.publish(event)
        self.assertEqual(seen, [event.event_id])
        self.assertEqual(bus.subscriber_errors, ["RuntimeError"])

    def test_policy_default_deny_and_approval(self):
        policy = ActionPolicy()
        self.assertTrue(policy.evaluate("inspect_posture").allowed)
        self.assertFalse(policy.evaluate("shell").allowed)
        decision = policy.evaluate("terminate_process")
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.requires_approval)
        self.assertTrue(policy.evaluate("terminate_process", approval_granted=True).allowed)
        with self.assertRaises(ValueError):
            ActionPolicy(allowed_read_actions={"same"}, approval_actions={"same"})

    def test_detection_produces_evidence_finding(self):
        engine = DetectionEngine([DetectionRule("R1", "Encoded process", "process.start", {"encoded": True}, "high", 0.9)])
        event = Event("process.start", "collector", {"encoded": True, "pid": 42})
        result = engine.process(event)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")
        self.assertEqual(result[0].evidence[0].source, "collector")
        self.assertEqual(result[0].evidence[0].event_id, event.event_id)
        self.assertEqual(engine.process(Event("process.start", "collector", {"encoded": False})), [])
        with self.assertRaises(ValueError):
            DetectionRule("R", "title", "x", {"bad": float("nan")})
        rule = DetectionRule("R", "title", "x", {"items": [1]})
        with self.assertRaises(TypeError):
            rule.field_equals["items"].append(2)

    def test_evidence_and_finding_timestamps_normalize_to_utc(self):
        evidence = Evidence("event", "summary", "source", "2026-11-23T15:00:00+05:30")
        self.assertTrue(evidence.observed_at.endswith("+00:00"))
        finding = Finding("R", "title", "low", 0.5, (evidence,), created_at="2026-11-23T15:00:00+05:30")
        self.assertTrue(finding.created_at.endswith("+00:00"))

    def test_finding_requires_evidence_and_valid_confidence(self):
        with self.assertRaises(ValueError):
            Finding("R", "title", "high", 0.8, ())
        with self.assertRaises(ValueError):
            Finding("R", "title", "high", 1.1, (Evidence("e", "summary", "source"),))
        with self.assertRaises(TypeError):
            Finding("R", "title", "high", 0.8, ("not evidence",))

    def test_bus_attachment_emits_findings(self):
        bus = EventBus()
        engine = DetectionEngine([DetectionRule("R", "title", "x", {})])
        engine.attach(bus)
        bus.publish(Event("x", "source", {}))
        self.assertEqual(len(engine.findings), 1)

    def test_duplicate_rule_rejected_and_findings_bounded(self):
        engine = DetectionEngine(max_findings=2)
        rule = DetectionRule("R", "title", "type", {})
        engine.add_rule(rule)
        with self.assertRaises(ValueError):
            engine.add_rule(rule)
        for _ in range(3):
            engine.process(Event("type", "source", {}))
        self.assertEqual(len(engine.findings), 2)


if __name__ == "__main__":
    unittest.main()
