import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.security import ApprovalRequired, AuditLog, SecurityPolicy
from jarvis.tools import Tool, ToolRegistry, list_workspace_files, read_workspace_file, create_workspace_file


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.audit = AuditLog(self.root / "audit.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_schema_validation_blocks_invalid_args_before_handler(self):\n        called = []\n        registry = ToolRegistry(SecurityPolicy(lambda *_: True), self.audit)\n        schema = {\"type\": \"object\", \"properties\": {\"value\": {\"type\": \"integer\"}}, \"required\": [\"value\"], \"additionalProperties\": False}\n        registry.register(Tool(\"safe\", \"test\", \"read\", lambda value: called.append(value), schema))\n        for invalid in ({}, {\"value\": \"1\"}, {\"value\": 1, \"extra\": True}, []):\n            with self.assertRaises(ValueError):\n                registry.execute(\"safe\", invalid)\n        self.assertEqual(called, [])\n\n    def test_schema_validation_blocks_nonfinite_numbers(self):\n        registry = ToolRegistry(SecurityPolicy(), self.audit)\n        schema = {\"type\": \"object\", \"properties\": {\"value\": {\"type\": \"number\"}}, \"required\": [\"value\"], \"additionalProperties\": False}\n        registry.register(Tool(\"numeric\", \"test\", \"read\", lambda value: value, schema))\n        for value in (float(\"nan\"), float(\"inf\"), True):\n            with self.assertRaises(ValueError):\n                registry.execute(\"numeric\", {\"value\": value})\n\n    def test_read_tool_does_not_need_approval(self):
        registry = ToolRegistry(SecurityPolicy(lambda *_: False), self.audit)
        registry.register(Tool("read", "test", "read", lambda: "ok"))
        self.assertEqual(registry.execute("read"), "ok")

    def test_write_tool_requires_approval(self):
        registry = ToolRegistry(SecurityPolicy(lambda *_: False), self.audit)
        registry.register(Tool("write", "test", "write", lambda: "written"))
        with self.assertRaises(ApprovalRequired):
            registry.execute("write")
        self.assertEqual(self.audit.recent()[0]["outcome"], "denied")

    def test_workspace_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            list_workspace_files(str(self.root), "../")
        with self.assertRaises(ValueError):
            read_workspace_file(str(self.root), "../secret.txt")

    def test_create_file_never_overwrites(self):
        create_workspace_file(str(self.root), "notes/one.txt", "hello")
        with self.assertRaises(FileExistsError):
            create_workspace_file(str(self.root), "notes/one.txt", "replace")


if __name__ == "__main__":
    unittest.main()
