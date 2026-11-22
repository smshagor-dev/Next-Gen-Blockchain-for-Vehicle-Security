import hashlib
import tempfile
import unittest
from pathlib import Path
from research_contracts.authentic_dataset_manifest import verify_manifest


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        data = b"fixture,not,publishable\n"
        (self.root / "data.csv").write_bytes(data)
        self.manifest = {
            "dataset": "veremi-nextgen", "source_url": "https://example.org/source",
            "license": "research-only", "acquired_utc": "2026-11-22T00:00:00Z",
            "files": [{"path": "data.csv", "sha256": hashlib.sha256(data).hexdigest(),
                       "bytes": len(data), "role": "raw"}]}

    def test_valid_fixture_only(self):
        self.assertEqual(len(verify_manifest(self.root, self.manifest)["verified_files"]), 1)

    def test_tampering_rejected(self):
        (self.root / "data.csv").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            verify_manifest(self.root, self.manifest)

    def test_path_escape_rejected(self):
        self.manifest["files"][0]["path"] = "../outside.csv"
        with self.assertRaises((ValueError, FileNotFoundError)):
            verify_manifest(self.root, self.manifest)

    def test_duplicate_rejected(self):
        self.manifest["files"].append(dict(self.manifest["files"][0]))
        with self.assertRaises(ValueError):
            verify_manifest(self.root, self.manifest)

    def test_boolean_length_rejected(self):
        self.manifest["files"][0]["bytes"] = True
        with self.assertRaises(ValueError):
            verify_manifest(self.root, self.manifest)

    def test_missing_source_rejected(self):
        self.manifest["source_url"] = ""
        with self.assertRaises(ValueError):
            verify_manifest(self.root, self.manifest)


if __name__ == "__main__":
    unittest.main()
