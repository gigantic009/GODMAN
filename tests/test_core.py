"""Offline unit tests for the Phase 1 conversation core."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from jarvis.core import AssistantCore, MAX_HISTORY_MESSAGES, MAX_USER_MESSAGE_CHARS


class AssistantCoreTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.assistant = AssistantCore(
            api_key="not-used-in-tests",
            model="test-model",
            assistant_name="GODMAN",
            client=self.client,
        )

    def test_returns_model_text_and_saves_turn(self):
        self.client.responses.create.return_value = SimpleNamespace(
            output_text="Hello. Ready when you are."
        )

        answer = self.assistant.respond("Hello")

        self.assertEqual(answer, "Hello. Ready when you are.")
        self.assertEqual(
            self.assistant.history,
            [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hello. Ready when you are."},
            ],
        )

    def test_trims_blank_input(self):
        with self.assertRaises(ValueError):
            self.assistant.respond("   ")
        self.client.responses.create.assert_not_called()

    def test_rejects_oversized_input(self):
        with self.assertRaises(ValueError):
            self.assistant.respond("x" * (MAX_USER_MESSAGE_CHARS + 1))
        self.client.responses.create.assert_not_called()

    def test_failed_api_call_does_not_corrupt_history(self):
        self.client.responses.create.side_effect = RuntimeError("offline")
        with self.assertRaises(RuntimeError):
            self.assistant.respond("Try this")
        self.assertEqual(self.assistant.history, [])

    def test_history_remains_bounded(self):
        self.client.responses.create.return_value = SimpleNamespace(output_text="OK")
        for index in range(15):
            self.assistant.respond(f"message {index}")
        self.assertLessEqual(len(self.assistant.history), MAX_HISTORY_MESSAGES)
        self.assertEqual(self.assistant.history[-1]["role"], "assistant")


if __name__ == "__main__":
    unittest.main()
