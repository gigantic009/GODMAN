import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.windows_events import collect_windows_security_events


class WindowsEventCollectorTests(unittest.TestCase):
    @patch("jarvis.windows_events.platform.system", return_value="Linux")
    def test_refuses_non_windows(self, _):
        with self.assertRaises(OSError):
            collect_windows_security_events()

    @patch("jarvis.windows_events.subprocess.run")
    @patch("jarvis.windows_events.platform.system", return_value="Windows")
    def test_collects_and_redacts(self, _, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps({
            "collected_at": "2026-11-19T00:00:00Z",
            "events": [{"log": "Security", "id": 4625, "message": "password=abc test@example.com"}]
        }), stderr="")
        result = collect_windows_security_events()
        message = result["events"][0]["message"]
        self.assertIn("[REDACTED]", message)
        self.assertNotIn("test@example.com", message)
        self.assertFalse(run.call_args.kwargs["shell"])

    @patch("jarvis.windows_events.subprocess.run")
    @patch("jarvis.windows_events.platform.system", return_value="Windows")
    def test_hides_powershell_errors(self, _, run):
        run.return_value = Mock(returncode=1, stdout="", stderr="private")
        with self.assertRaisesRegex(RuntimeError, "collection failed"):
            collect_windows_security_events()


if __name__ == "__main__":
    unittest.main()
