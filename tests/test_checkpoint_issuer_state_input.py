"""Negative controls for untrusted persisted checkpoint state (no hardware)."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from research_contracts.independent_checkpoint_issuer import (
    CheckpointRefused, IndependentCheckpointIssuer,
    MAX_CHECKPOINT_STATE_BYTES, MAX_CHECKPOINT_BLOCKS,
)

KEY = b"simulation-only-issuer-key-32bytes-long"
VEHICLE = "state-input-negative-control"

def digest(label):
    return hashlib.sha256(label.encode()).hexdigest()

class IssuerStateInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.issuer = IndependentCheckpointIssuer(self.temp.name, VEHICLE, KEY)
        self.baseline = [digest("genesis")]
        self.issuer.issue(self.baseline)

    def test_oversized_regular_state_rejected_without_rewrite(self):
        path = self.issuer.path
        path.write_bytes(b" " * (MAX_CHECKPOINT_STATE_BYTES + 1))
        with self.assertRaisesRegex(CheckpointRefused, "byte limit"):
            self.issuer.issue(self.baseline + [digest("next")])
        self.assertEqual(path.stat().st_size, MAX_CHECKPOINT_STATE_BYTES + 1)

    def test_oversized_pins_array_rejected_even_if_json_valid(self):
        path = self.issuer.path
        state = {"vehicle": VEHICLE, "revision": 1,
                 "pins": [digest("x")] * (MAX_CHECKPOINT_BLOCKS + 1)}
        path.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaises(CheckpointRefused):
            self.issuer.issue(self.baseline)

    @unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "POSIX symlink")
    def test_symlink_state_rejected_and_target_untouched(self):
        target = Path(self.temp.name) / "external.json"
        target.write_text(self.issuer.path.read_text(), encoding="utf-8")
        self.issuer.path.unlink()
        self.issuer.path.symlink_to(target)
        before = target.read_bytes()
        with self.assertRaises(CheckpointRefused):
            self.issuer.issue(self.baseline + [digest("next")])
        self.assertEqual(target.read_bytes(), before)

    @unittest.skipUnless(hasattr(os, "mkfifo") and os.name == "posix", "POSIX FIFO")
    def test_fifo_state_refused_without_blocking(self):
        self.issuer.path.unlink()
        os.mkfifo(self.issuer.path)
        with self.assertRaises(CheckpointRefused):
            self.issuer.issue(self.baseline)

    def test_valid_state_still_supports_append_and_restart(self):
        appended = self.baseline + [digest("next")]
        receipt = self.issuer.issue(appended)
        restarted = IndependentCheckpointIssuer(self.temp.name, VEHICLE, KEY)
        self.assertEqual(restarted.issue(appended), receipt)
        with self.assertRaisesRegex(CheckpointRefused, "truncation"):
            restarted.issue(self.baseline)

if __name__ == "__main__":
    unittest.main()
