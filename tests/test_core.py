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
        self.assistant = AssistantCore("unused", "test-model", "GODMAN", client=self.client)

    def test_returns_model_text_and_saves_turn(self):
        self.client.responses.create.return_value = SimpleNamespace(output_text="Hello.", output=[])
        self.assertEqual(self.assistant.respond("Hello"), "Hello.")
        self.assertEqual(self.assistant.history[-1], {"role": "assistant", "content": "Hello."})

    def test_rejects_blank_and_oversized_input(self):
        with self.assertRaises(ValueError):
            self.assistant.respond(" ")
        with self.assertRaises(ValueError):
            self.assistant.respond("x" * (MAX_USER_MESSAGE_CHARS + 1))
        self.client.responses.create.assert_not_called()

    def test_failed_api_call_does_not_corrupt_history(self):
        self.client.responses.create.side_effect = RuntimeError("offline")
        with self.assertRaises(RuntimeError):
            self.assistant.respond("Try")
        self.assertEqual(self.assistant.history, [])

    def test_history_remains_bounded(self):
        self.client.responses.create.return_value = SimpleNamespace(output_text="OK", output=[])
        for index in range(15):
            self.assistant.respond(f"message {index}")
        self.assertLessEqual(len(self.assistant.history), MAX_HISTORY_MESSAGES)

    def test_calls_registered_tool_and_returns_final_answer(self):
        tool_call = SimpleNamespace(type="function_call", name="system_summary",
                                    arguments="{}", call_id="call_123")
        first = SimpleNamespace(output=[tool_call], output_text="", id="resp_1")
        second = SimpleNamespace(output=[], output_text="Your system summary is ready.", id="resp_2")
        self.client.responses.create.side_effect = [first, second]
        registry = Mock()
        registry.model_tools.return_value = [{"type": "function", "name": "system_summary"}]
        registry.execute.return_value = {"system": "Windows"}
        assistant = AssistantCore("unused", "test-model", client=self.client, tool_registry=registry)
        answer = assistant.respond("Summarize my computer")
        self.assertEqual(answer, "Your system summary is ready.")
        registry.execute.assert_called_once_with("system_summary", {})
        self.assertEqual(self.client.responses.create.call_count, 2)


if __name__ == "__main__":
    unittest.main()
