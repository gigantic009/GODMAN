import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.security import ApprovalRequired, AuditLog, SecurityPolicy
from jarvis.defense_core.policy import ActionPolicy
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

    def test_integer_schema_rejects_overflowing_integer_values(self):
        registry = ToolRegistry(SecurityPolicy(), self.audit)
        schema = {"type": "object", "properties": {"value": {"type": "integer"}},
                  "required": ["value"], "additionalProperties": False}
        registry.register(Tool("integer_overflow", "test", "read", lambda value: value, schema))
        with self.assertRaises(ValueError):
            registry.execute("integer_overflow", {"value": 10**1000})

    def test_schema_definitions_are_rejected_at_registration(self):
        invalid = [
            {"type": "object", "properties": {"value": {"type": "string", "pattern": "x"}},
             "required": ["value"], "additionalProperties": False},
            {"type": "object", "properties": {"value": {"type": "string"}},
             "required": [], "additionalProperties": False},
            {"type": "object", "properties": {"value": {"type": "string"}},
             "required": ["value"], "additionalProperties": True},
            {"type": "array", "minItems": 2, "maxItems": 1, "items": {"type": "string"}},
            {"type": "array", "items": {}},
            {"type": "array", "items": {"type": "string"}},
            {"type": "object", "properties": {"value": {"type": "integer", "enum": [True]}},
             "required": ["value"], "additionalProperties": False},
            {"type": "object", "properties": {"value": {"type": "string", "maxLength": 100001}},
             "required": ["value"], "additionalProperties": False},
            {"type": "object", "properties": {"value": {"type": "number", "minimum": float("inf")}},
             "required": ["value"], "additionalProperties": False},
            {"properties": {}, "required": [], "additionalProperties": False},
        ]
        for schema in invalid:
            with self.subTest(schema=schema):
                registry = ToolRegistry(SecurityPolicy(), self.audit)
                with self.assertRaises(ValueError):
                    registry.register(Tool("invalid", "test", "read", lambda **kwargs: None, schema))

    def test_nested_array_schema_bounds_and_item_types(self):
        schema = {"type": "object", "properties": {
            "items": {"type": "array", "minItems": 1, "maxItems": 2,
                      "items": {"type": "string", "minLength": 1, "maxLength": 4}}
        }, "required": ["items"], "additionalProperties": False}
        registry = ToolRegistry(SecurityPolicy(), self.audit)
        registry.register(Tool("array_bound", "test", "read", lambda items: len(items), schema))
        self.assertEqual(registry.execute("array_bound", {"items": ["a", "abcd"]}), 2)
        for value in ({"items": []}, {"items": ["too-long"]}, {"items": [1]}):
            with self.assertRaises(ValueError):
                registry.execute("array_bound", value)

    def test_registered_schema_is_snapshotted_and_enum_is_type_strict(self):
        schema = {"type": "object", "properties": {"value": {"type": "integer", "enum": [1]}},
                  "required": ["value"], "additionalProperties": False}
        registry = ToolRegistry(SecurityPolicy(), self.audit)
        registry.register(Tool("snap", "test", "read", lambda value: "ok", schema))
        schema["properties"]["value"]["enum"].append(2)
        exported = registry.model_tools()[0]["parameters"]
        exported["properties"]["value"]["enum"].append(2)
        self.assertEqual(registry.execute("snap", {"value": 1}), "ok")
        with self.assertRaises(ValueError):
            registry.execute("snap", {"value": 2})
        with self.assertRaises(ValueError):
            registry.execute("snap", {"value": True})

    def test_number_schema_rejects_overflowing_integer_values(self):
        registry = ToolRegistry(SecurityPolicy(), self.audit)
        schema = {"type": "object", "properties": {"value": {"type": "number"}},
                  "required": ["value"], "additionalProperties": False}
        registry.register(Tool("numeric_overflow", "test", "read", lambda value: value, schema))
        with self.assertRaises(ValueError):
            registry.execute("numeric_overflow", {"value": 10**1000})

    def test_audit_redacts_secrets_and_email(self):
        self.audit.record("test", "read", "success", "api_key=abc123 user@example.com")
        details = self.audit.recent()[0]["details"]
        self.assertNotIn("abc123", details)
        self.assertNotIn("user@example.com", details)
        self.assertIn("[REDACTED]", details)
        self.assertIn("[EMAIL]", details)

    def test_registry_has_no_market_tools(self):
        from jarvis.tools import build_default_registry
        registry = build_default_registry(self.root / "data", self.root / "workspace", SecurityPolicy())
        names = [item["name"] for item in registry.describe()]
        self.assertFalse(any("market" in name.lower() or "stock" in name.lower() for name in names))

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

    def test_dispatch_uses_central_policy_and_denies_unlisted_read_action(self):
        called = []
        central = ActionPolicy(allowed_read_actions=set(), approval_actions={"tool:write"})
        registry = ToolRegistry(SecurityPolicy(lambda *_: True), self.audit, central)
        registry.register(Tool("read", "test", "read", lambda: called.append(True)))
        with self.assertRaises(PermissionError):
            registry.execute("read")
        self.assertEqual(called, [])
        self.assertEqual(self.audit.recent()[0]["outcome"], "denied")

    def test_read_action_cannot_be_promoted_to_approval_scope(self):
        approved = []
        central = ActionPolicy(allowed_read_actions=set(), approval_actions={"tool:read"})
        registry = ToolRegistry(SecurityPolicy(lambda *_: approved.append(True) or True), self.audit, central)
        registry.register(Tool("read", "test", "read", lambda: "should not run"))
        with self.assertRaises(PermissionError):
            registry.execute("read")
        self.assertEqual(approved, [])
        self.assertEqual(self.audit.recent()[0]["outcome"], "denied")

    def test_custom_policy_denies_write_even_when_approval_callback_accepts(self):
        central = ActionPolicy(allowed_read_actions=set(), approval_actions=set())
        registry = ToolRegistry(SecurityPolicy(lambda *_: True), self.audit, central)
        registry.register(Tool("write", "test", "write", lambda: "should not run"))
        with self.assertRaises(PermissionError):
            registry.execute("write")

    def test_write_requires_explicit_approval_after_policy_gate(self):
        registry = ToolRegistry(SecurityPolicy(lambda *_: True), self.audit)
        registry.register(Tool("write", "test", "write", lambda: "approved"))
        self.assertEqual(registry.execute("write"), "approved")

    def test_tool_risk_class_is_validated_at_registration(self):
        registry = ToolRegistry(SecurityPolicy(), self.audit)
        with self.assertRaises(ValueError):
            registry.register(Tool("unsafe", "test", "unknown", lambda: None))

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
