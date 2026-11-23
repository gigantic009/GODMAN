import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
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
