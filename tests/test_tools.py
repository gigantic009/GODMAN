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

    def test_schema_validation_blocks_invalid_args_before_handler(self):
        called = []
        registry = ToolRegistry(SecurityPolicy(lambda *_: True), self.audit)
        schema = {"type": "object", "properties": {"value": {"type": "integer"}}, "required": ["value"], "additionalProperties": False}
        registry.register(Tool("safe", "test", "read", lambda value: called.append(value), schema))
        for invalid in ({}, {"value": "1"}, {"value": 1, "extra": True}, []):
            with self.assertRaises(ValueError):
                registry.execute("safe", invalid)
        self.assertEqual(called, [])

    def test_schema_validation_blocks_nonfinite_numbers(self):
        registry = ToolRegistry(SecurityPolicy(), self.audit)
        schema = {"type": "object", "properties": {"value": {"type": "number"}}, "required": ["value"], "additionalProperties": False}
        registry.register(Tool("numeric", "test", "read", lambda value: value, schema))
        for value in (float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                registry.execute("numeric", {"value": value})

    def test_array_bounds_and_integer_range_are_enforced(self):
        registry = ToolRegistry(SecurityPolicy(), self.audit)
        schema = {"type": "object", "properties": {
            "items": {"type": "array", "minItems": 1, "maxItems": 2, "items": {"type": "integer"}},
            "count": {"type": "integer", "minimum": 1, "maximum": 3}
        }, "required": ["items", "count"], "additionalProperties": False}
        registry.register(Tool("bounded", "test", "read", lambda items, count: "ok", schema))
        for args in ({"items": [], "count": 1}, {"items": [1, 2, 3], "count": 1},
                     {"items": [1], "count": 0}, {"items": [1], "count": 4}):
            with self.assertRaises(ValueError):
                registry.execute("bounded", args)
        self.assertEqual(registry.execute("bounded", {"items": [1, 2], "count": 2}), "ok")

    def test_read_tool_does_not_need_approval(self):
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
