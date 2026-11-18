import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.checkup import run_endpoint_checkup


class EndpointCheckupTests(unittest.TestCase):
    @patch("jarvis.checkup.platform.system", return_value="Linux")
    def test_non_windows_returns_safe_explanation(self, _):
        result = run_endpoint_checkup()
        self.assertEqual(result["checkup"], "unsupported_platform")
        self.assertEqual(result["actions_taken"], [])

    @patch("jarvis.checkup.platform.system", return_value="Windows")
    def test_aggregates_read_only_findings_and_events(self, _):
        result = run_endpoint_checkup(
            posture_collector=lambda: {"checks": {"defender": {
                "available": True, "antivirus_enabled": True,
                "real_time_protection": False, "behavior_monitoring": True,
                "ioav_protection": True, "signatures_age_days": 5,
            }}},
            firewall_collector=lambda: {"findings": [{
                "severity": "high", "finding": "Inbound policy is not default deny",
            }]},
            events_collector=lambda: {"events": [{"id": 4625}, {"id": 1116}]},
        )
        self.assertEqual(result["checkup"], "completed")
        self.assertEqual(result["summary"]["high_findings"], 3)
        self.assertTrue(any("malware detection" in item["finding"] for item in result["findings"]))
        self.assertEqual(result["summary"]["events_returned"], 2)
        self.assertEqual(result["actions_taken"], [])
        self.assertTrue(result["read_only"])

    @patch("jarvis.checkup.platform.system", return_value="Windows")
    def test_collector_failure_does_not_hide_other_sections(self, _):
        def fail():
            raise PermissionError()
        result = run_endpoint_checkup(
            posture_collector=fail,
            firewall_collector=lambda: {"findings": []},
            events_collector=lambda: {"events": []},
        )
        self.assertEqual(result["checkup"], "completed_with_gaps")
        self.assertEqual(result["summary"]["collector_errors"], 1)
        self.assertEqual(result["sections"]["security_posture"]["error"], "PermissionError")
        self.assertIn("firewall", result["sections"])


if __name__ == "__main__":
    unittest.main()
