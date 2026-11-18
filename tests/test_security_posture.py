import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.security_posture import collect_windows_security_posture


class WindowsPostureTests(unittest.TestCase):
    @patch("jarvis.security_posture.platform.system", return_value="Linux")
    def test_refuses_non_windows(self, _):
        with self.assertRaises(OSError):
            collect_windows_security_posture()

    @patch("jarvis.security_posture.subprocess.run")
    @patch("jarvis.security_posture.platform.system", return_value="Windows")
    def test_parses_read_only_snapshot(self, _, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps({
            "defender": {"available": True, "real_time_protection": True},
            "firewall": {"available": True, "profiles": [{"name": "Domain", "enabled": True}]},
            "bitlocker": {"available": True, "volumes": []},
            "recent_hotfixes": []
        }), stderr="")
        result = collect_windows_security_posture()
        self.assertEqual(result["collection"], "read_only")
        self.assertTrue(result["checks"]["defender"]["real_time_protection"])
        self.assertFalse(run.call_args.kwargs["shell"])

    @patch("jarvis.security_posture.subprocess.run")
    @patch("jarvis.security_posture.platform.system", return_value="Windows")
    def test_does_not_leak_command_stderr(self, _, run):
        run.return_value = Mock(returncode=1, stdout="", stderr="sensitive path")
        with self.assertRaisesRegex(RuntimeError, "query failed"):
            collect_windows_security_posture()

    @patch("jarvis.security_posture.subprocess.run")
    @patch("jarvis.security_posture.platform.system", return_value="Windows")
    def test_rejects_oversized_output(self, _, run):
        run.return_value = Mock(returncode=0, stdout="x" * 100001, stderr="")
        with self.assertRaisesRegex(RuntimeError, "oversized"):
            collect_windows_security_posture()


if __name__ == "__main__":
    unittest.main()
