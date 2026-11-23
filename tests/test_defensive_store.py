import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.defense_core import Event, EventBus, DetectionRule, DetectionEngine, Evidence, Finding
from jarvis.defense_core.store import LocalKnowledgeStore


class LocalStoreTests(unittest.TestCase):
    def test_roundtrip_event_and_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalKnowledgeStore(Path(tmp) / "knowledge.sqlite", retention=100)
            bus = EventBus()
            engine = DetectionEngine([DetectionRule("R1", "test finding", "test", {"flag": True})], store=store)
            engine.attach(bus)
            event = Event("test", "fixture", {"flag": True})
            bus.publish(event)
            self.assertEqual(store.recent_events()[0]["event_id"], event.event_id)
            findings = store.recent_findings()
            self.assertEqual(findings[0]["rule_id"], "R1")
            self.assertEqual(findings[0]["evidence"][0]["event_id"], event.event_id)

    def test_reject_invalid_objects_and_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = LocalKnowledgeStore(Path(tmp) / "db.sqlite")
            with self.assertRaises(TypeError):
                store.save_event({})
            with self.assertRaises(TypeError):
                store.save_finding({})
            with self.assertRaises(ValueError):
                LocalKnowledgeStore(Path(tmp) / "other.sqlite", retention=10)
            with self.assertRaises(TypeError):
                store.recent_events(True)


if __name__ == "__main__":
    unittest.main()
