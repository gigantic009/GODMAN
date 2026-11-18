import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.security import SecurityPolicy
from jarvis.tools import build_default_registry


class SecurityToolRegistrationTests(unittest.TestCase):
    def test_security_and_market_tools_are_explicitly_registered(self):
        with tempfile.TemporaryDirectory() as temp:
            registry = build_default_registry(Path(temp) / "data", Path(temp) / "workspace", SecurityPolicy())
            names = {item["name"] for item in registry.describe()}
            self.assertTrue({
                "analyze_security_log",
                "inspect_file_static",
                "sha256_workspace_file",
                "collect_windows_security_posture",
                "inspect_zip_safety",
                "analyze_market_prices",
            }.issubset(names))
            self.assertNotIn("run_shell_command", names)
            self.assertNotIn("execute_powershell", names)

    def test_every_model_tool_has_strict_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            registry = build_default_registry(Path(temp) / "data", Path(temp) / "workspace", SecurityPolicy())
            for tool in registry.model_tools():
                self.assertTrue(tool["strict"])
                self.assertEqual(tool["parameters"].get("additionalProperties"), False)
                self.assertEqual(set(tool["parameters"].get("properties", {})), set(tool["parameters"].get("required", [])))


if __name__ == "__main__":
    unittest.main()
