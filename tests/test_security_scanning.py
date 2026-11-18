import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from jarvis import security_scanning


class DefenderScanTests(unittest.TestCase):
    def test_rejects_workspace_root_and_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(security_scanning.platform, "system", return_value="Windows"):
                with self.assertRaises(ValueError):
                    security_scanning.scan_with_microsoft_defender(root, ".")
                with self.assertRaises(ValueError):
                    security_scanning.scan_with_microsoft_defender(root, "../outside")

    def test_missing_target_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(security_scanning.platform, "system", return_value="Windows"):
                with self.assertRaises(FileNotFoundError):
                    security_scanning.scan_with_microsoft_defender(temp, "missing.exe")

    @patch("jarvis.security_scanning.subprocess.run")
    @patch("jarvis.security_scanning._defender_cli")
    def test_uses_fixed_defender_arguments_without_shell(self, scanner, run):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "sample.txt"
            target.write_text("benign test")
            scanner.return_value = Path("C:/Defender/MpCmdRun.exe")
            run.return_value = Mock(returncode=0, stdout="scan complete", stderr="")
            with patch.object(security_scanning.platform, "system", return_value="Windows"):
                result = security_scanning.scan_with_microsoft_defender(temp, "sample.txt")
            args, kwargs = run.call_args
            self.assertIn("-Scan", args[0])
            self.assertIn("-ScanType", args[0])
            self.assertIn("-File", args[0])
            self.assertFalse(kwargs["shell"])
            self.assertEqual(result["scan"], "completed")
            self.assertIn("does not prove", result["limitations"][0])

    @patch("jarvis.security_scanning.subprocess.run")
    @patch("jarvis.security_scanning._defender_cli")
    def test_timeout_is_reported(self, scanner, run):
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "sample.txt"
            target.write_text("benign test")
            scanner.return_value = Path("C:/Defender/MpCmdRun.exe")
            run.side_effect = subprocess.TimeoutExpired("MpCmdRun.exe", 30)
            with patch.object(security_scanning.platform, "system", return_value="Windows"):
                with self.assertRaises(TimeoutError):
                    security_scanning.scan_with_microsoft_defender(temp, "sample.txt")


if __name__ == "__main__":
    unittest.main()
