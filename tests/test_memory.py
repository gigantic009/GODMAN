import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.memory import MemoryStore


class MemoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = MemoryStore(Path(self.temp.name) / "memory.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_remember_search_and_forget(self):
        memory_id = self.store.remember("User prefers concise project updates", "preference")
        results = self.store.search("concise")
        self.assertEqual(results[0]["id"], memory_id)
        self.assertTrue(self.store.forget(memory_id))
        self.assertEqual(self.store.search("concise"), [])

    def test_conversation_persistence(self):
        self.store.save_message("user", "Hello")
        self.store.save_message("assistant", "Hi")
        self.assertEqual(self.store.recent_conversation(), [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi"},
        ])


if __name__ == "__main__":
    unittest.main()
