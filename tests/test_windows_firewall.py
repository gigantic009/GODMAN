import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.windows_firewall import inspect_windows_firewall


class WindowsFirewallInspectionTests(unittest.TestCase):
    @patch("jarvis.windows_firewall.platform.system", return_value="Linux")
    def test_refuses_non_windows(self, _):
        with self.assertRaises(OSError):
            inspect_windows_firewall()

    @patch("jarvis.windows_firewall.subprocess.run")
    @patch("jarvis.windows_firewall.platform.system", return_value="Windows")
    def test_returns_read_only_baseline_plan(self, _, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps({
            "profiles": [{
                "name": "Public", "enabled": True, "default_inbound": "Block",
                "default_outbound": "Allow"
            }],
            "enabled_inbound_allow_rules": [],
            "rules_truncated": False,
        }), stderr="")
        result = inspect_windows_firewall()
        self.assertEqual(result["collection"], "read_only")
        self.assertEqual(result["baseline_plan"]["enforcement"], "NOT_APPLIED")
        self.assertTrue(result["baseline_plan"]["approval_required"])
        self.assertFalse(run.call_args.kwargs["shell"])

    @patch("jarvis.windows_firewall.subprocess.run")
    @patch("jarvis.windows_firewall.platform.system", return_value="Windows")
    def test_flags_disabled_firewall(self, _, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps({
            "profiles": [{
                "name": "Public", "enabled": False, "default_inbound": "Allow",
                "default_outbound": "Allow"
            }],
            "enabled_inbound_allow_rules": [],
            "rules_truncated": False,
        }), stderr="")
        result = inspect_windows_firewall()
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(result["findings"][0]["severity"], "high")

    @patch("jarvis.windows_firewall.subprocess.run")
    @patch("jarvis.windows_firewall.platform.system", return_value="Windows")
    def test_hides_powershell_error_details(self, _, run):
        run.return_value = Mock(returncode=1, stdout="", stderr="private system path")
        with self.assertRaisesRegex(RuntimeError, "inspection failed"):
            inspect_windows_firewall()


if __name__ == "__main__":
    unittest.main()
