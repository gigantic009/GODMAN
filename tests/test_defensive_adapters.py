import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.defense_core import EventBus
from jarvis.defense_core.adapters import AdapterCapability, AdapterRegistry


class FakeAdapter:
    platform = "fixture"

    def capabilities(self):
        return [AdapterCapability("processes", "fixture", True), AdapterCapability("network", "fixture", False)]

    def collect(self, capability, *, limit=100):
        return [{"sample": i} for i in range(min(limit, 2))]


class AdapterTests(unittest.TestCase):
    def test_capability_gating_and_bounds(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter())
        self.assertEqual(registry.platforms(), ["fixture"])
        self.assertEqual(registry.collect("fixture", "processes", limit=2), [{"sample": 0}, {"sample": 1}])
        with self.assertRaises(ValueError):
            registry.collect("fixture", "network")
        with self.assertRaises(ValueError):
            registry.collect("fixture", "processes", limit=501)

    def test_normalization_publishes_eventbus_events(self):
        registry = AdapterRegistry()
        registry.register(FakeAdapter())
        bus = EventBus()
        events = registry.collect_events("fixture", "processes", limit=2, host_id="fixture-host", event_bus=bus)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "endpoint.processes")
        self.assertEqual(events[0].source, "adapter:fixture")
        self.assertEqual(events[0].data["record"], {"sample": 0})
        self.assertEqual(events[0].host_id, "fixture-host")
        self.assertEqual(bus.history(), events)

    def test_normalizer_rejects_unbounded_or_non_json_data(self):
        class BadAdapter(FakeAdapter):
            def collect(self, capability, *, limit=100):
                return [{"data": object()}]
        registry = AdapterRegistry()
        registry.register(BadAdapter())
        with self.assertRaises(TypeError):
            registry.collect_events("fixture", "processes")

    def test_duplicate_and_unknown_platform(self):
        registry = AdapterRegistry()
        adapter = FakeAdapter()
        registry.register(adapter)
        with self.assertRaises(ValueError):
            registry.register(adapter)
        with self.assertRaises(KeyError):
            registry.get("unknown")


if __name__ == "__main__":
    unittest.main()
