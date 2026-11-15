"""Synthetic integrity regression only; not experimental evidence."""
import hashlib
import json
import unittest
from verify_pinned_replay_trial import verify

def encode(obj):
    return json.dumps(obj, sort_keys=True).encode()

def sha(b):
    return hashlib.sha256(b).hexdigest()

class PinnedTrialTests(unittest.TestCase):
    def setUp(self):
        self.source = b'{"incident_id":"i1"}\n'
        self.truth = b'incident_id,cluster_id,should_alert\ni1,c1,1\n'
        self.capture = b'capture-data'
        self.policy = b'policy-v1'
        self.output = encode({"input_sha256": sha(self.source), "events": [{"incident_id": "i1", "verdict": "simulated_alert"}], "count": 1, "simulated_alerts": 1})
        self.manifest = {"schema_version": 1, "experiment_id": "e1", "scenario_id": "s1",
                         "seed": "1", "split": "test", "input_sha256": sha(self.source),
                         "truth_sha256": sha(self.truth), "capture_sha256": sha(self.capture),
                         "policy_sha256": sha(self.policy),
                         "window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:01:00Z"}

    def run_trial(self, manifest=None, output=None, pin=None, source=None, truth=None, capture=None, policy=None):
        m = encode(self.manifest if manifest is None else manifest)
        return verify(m, self.source if source is None else source,
                      self.output if output is None else output,
                      self.truth if truth is None else truth,
                      self.capture if capture is None else capture,
                      self.policy if policy is None else policy,
                      sha(m) if pin is None else pin)

    def test_valid(self):
        result = self.run_trial()
        self.assertEqual(result["decision_count"], 1)
        self.assertFalse(result["publication_ready"])

    def test_manifest_pin_mismatch(self):
        with self.assertRaises(ValueError):
            self.run_trial(pin="0" * 64)

    def test_source_tamper(self):
        with self.assertRaises(ValueError):
            self.run_trial(source=b"tampered")

    def test_truth_tamper(self):
        with self.assertRaises(ValueError):
            self.run_trial(truth=b"tampered")

    def test_capture_tamper(self):
        with self.assertRaises(ValueError):
            self.run_trial(capture=b"tampered")

    def test_policy_tamper(self):
        with self.assertRaises(ValueError):
            self.run_trial(policy=b"tampered")

    def test_training_split(self):
        with self.assertRaises(ValueError):
            self.run_trial(manifest={**self.manifest, "split": "train"})

    def test_naive_timestamp(self):
        with self.assertRaises(ValueError):
            self.run_trial(manifest={**self.manifest, "window_start": "2026-01-01T00:00:00"})

    def test_reversed_window(self):
        with self.assertRaises(ValueError):
            self.run_trial(manifest={**self.manifest, "window_end": "2025-01-01T00:00:00Z"})

    def test_duplicate_decisions(self):
        out = json.loads(self.output)
        out["events"].append(out["events"][0])
        out["count"] = 2
        out["simulated_alerts"] = 2
        with self.assertRaises(ValueError):
            self.run_trial(output=encode(out))

    def test_wrong_replay_input(self):
        out = json.loads(self.output)
        out["input_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.run_trial(output=encode(out))

    def test_duplicate_json_key(self):
        with self.assertRaises(ValueError):
            self.run_trial(output=b'{"input_sha256":"x","input_sha256":"y"}')

if __name__ == "__main__":
    unittest.main()
