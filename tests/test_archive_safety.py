import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jarvis.archive_safety import inspect_zip_safety


class ArchiveSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_reads_metadata_without_extracting(self):
        archive = self.root / "normal.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("docs/readme.txt", "hello world")
        result = inspect_zip_safety(self.root, "normal.zip")
        self.assertEqual(result["member_count"], 1)
        self.assertIn("No member was extracted", result["assessment"])

    def test_flags_high_compression_ratio(self):
        archive = self.root / "ratio.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("large.txt", "A" * 500_000)
        result = inspect_zip_safety(self.root, "ratio.zip")
        self.assertIn("high_compression_ratio", result["flags"])

    def test_flags_unsafe_member_paths(self):
        archive = self.root / "traversal.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("../outside.txt", "data")
            z.writestr("..\\\\outside-windows.txt", "data")
        result = inspect_zip_safety(self.root, "traversal.zip")
        self.assertIn("path_traversal_member_names", result["flags"])
        self.assertEqual(len(result["suspicious_member_paths"]), 2)

    def test_rejects_workspace_escape(self):
        with self.assertRaises(ValueError):
            inspect_zip_safety(self.root, "../outside.zip")

    def test_rejects_non_zip(self):
        (self.root / "bad.zip").write_text("not a zip", encoding="utf-8")
        with self.assertRaises(ValueError):
            inspect_zip_safety(self.root, "bad.zip")


if __name__ == "__main__":
    unittest.main()
