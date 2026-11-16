"""Synthetic integrity contracts, not independent experimental evidence."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from experiments.v2x.verify_pinned_coverage import verify
from experiments.v2x.audit_trial_coverage import CoverageError

class PinnedCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.paths = {}
        for name, value in {
            "world": "incident_id,cluster_id,truth\\na,A,1\\n",
            "candidate": "incident_id,alert\\na,1\\n",
            "baseline": "incident_id,alert\\n",
        }.items():
            self.paths[name] = root / (name + ".csv")
            self.paths[name].write_text(value.replace("\\n", "\n"))
        self.manifest = root / "manifest.json"
        self.data = {"protocol": "paired-world-coverage-pin-v1", "trial_id": "trial-01",
                     "split": "held_out", "seed": 4,
                     "inputs": {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in self.paths.items()}}
        self.save()

    def save(self):
        self.manifest.write_text(json.dumps(self.data, sort_keys=True))
        self.pin = hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def check(self):
        return verify(self.manifest, self.pin, **self.paths)

    def test_valid_pins_and_denominator(self):
        result = self.check()
        self.assertEqual(result["audit"]["world_incidents"], 1)
        self.assertEqual(result["audit"]["methods"]["baseline"]["confusion"]["fn"], 1)

    def test_tampered_prediction_rejected(self):
        self.paths["candidate"].write_text("incident_id,alert\na,0\n")
        with self.assertRaises(CoverageError):
            self.check()

    def test_manifest_mutation_rejected(self):
        self.manifest.write_text(self.manifest.read_text() + " ")
        with self.assertRaises(CoverageError):
            self.check()

    def test_non_held_out_rejected(self):
        self.data["split"] = "train"
        self.save()
        with self.assertRaises(CoverageError):
            self.check()

    def test_boolean_seed_rejected(self):
        self.data["seed"] = True
        self.save()
        with self.assertRaises(CoverageError):
            self.check()

    def test_duplicate_json_keys_rejected(self):
        self.manifest.write_text('{"trial_id":"a","trial_id":"b"}')
        self.pin = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with self.assertRaises(CoverageError):
            self.check()

if __name__ == "__main__":
    unittest.main()
