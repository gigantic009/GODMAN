import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.cybersecurity import analyze_security_log, extract_indicators, sha256_workspace_file


class CybersecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_extracts_indicators_and_classifies_private_ip(self):
        result = extract_indicators("failed login from 192.168.1.8 https://example.com/a " + "a" * 64)
        self.assertEqual(result["ipv4"][0]["scope"], "private")
        self.assertIn("https://example.com/a", result["urls"])
        self.assertEqual(result["file_hashes"][0], "a" * 64)

    def test_log_triage_flags_known_patterns(self):
        log = self.root / "sample.log"
        log.write_text("Failed password for root from 203.0.113.8\nPowerShell -EncodedCommand AAAA\n", encoding="utf-8")
        result = analyze_security_log(self.root, "sample.log")
        self.assertGreaterEqual(result["findings_count"], 2)
        self.assertIn("repeated_auth_failure", result["rule_counts"])
        self.assertIn("encoded_powershell", result["rule_counts"])

    def test_workspace_escape_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_security_log(self.root, "../outside.log")

    def test_unsupported_log_type_is_rejected(self):
        (self.root / "sample.exe").write_bytes(b"not a log")
        with self.assertRaises(ValueError):
            analyze_security_log(self.root, "sample.exe")

    def test_sha256_hash_is_deterministic(self):
        sample = self.root / "sample.txt"
        sample.write_text("hello", encoding="utf-8")
        result = sha256_workspace_file(self.root, "sample.txt")
        self.assertEqual(result["digest"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")


if __name__ == "__main__":
    unittest.main()
