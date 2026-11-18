import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.url_triage import analyze_url_structure


class URLTriageTests(unittest.TestCase):
    def test_flags_userinfo_and_ip_literal(self):
        result = analyze_url_structure("http://trusted.example@192.0.2.1/login")
        reasons = [item["reason"] for item in result["findings"]]
        self.assertTrue(any("user-information" in reason for reason in reasons))
        self.assertTrue(any("literal IP" in reason for reason in reasons))

    def test_normalizes_missing_scheme(self):
        result = analyze_url_structure("example.com")
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["hostname_ascii"], "example.com")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            analyze_url_structure("file:///etc/passwd")

    def test_does_not_visit_url(self):
        result = analyze_url_structure("https://bit.ly/abc")
        self.assertEqual(result["verdict"], "needs_review")


if __name__ == "__main__":
    unittest.main()
