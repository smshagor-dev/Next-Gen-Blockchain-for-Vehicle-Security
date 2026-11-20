"""Fail-closed type-confusion negative controls for non-actuating evidence admission."""
import tempfile
import unittest
from pathlib import Path

from research_contracts.epoch_admission_controls import EpochAdmission, Evidence
from research_contracts.durable_epoch_admission import DurableEpochAdmission


def observation(sender, verified=True):
    return Evidence(incident="type-confusion", sender=sender, epoch=0,
                    nonce="nonce-" + sender, event="hazard", verified=verified)


class StrictAuthorizationInputs(unittest.TestCase):
    def test_nonboolean_verified_never_counts_toward_quorum(self):
        for untrusted in ("true", "yes", 1, ["true"], {"verified": True}):
            with self.subTest(untrusted=repr(untrusted)):
                gate = EpochAdmission(quorum=2)
                self.assertFalse(gate.admit(observation("attacker", untrusted)))
                self.assertFalse(gate.admit(observation("legitimate")))
                self.assertTrue(gate.admit(observation("second")))

    def test_nonboolean_operator_confirmation_cannot_clear_stop(self):
        for untrusted in ("true", "yes", 1, ["yes"], {"confirmed": True}):
            with self.subTest(untrusted=repr(untrusted)):
                gate = EpochAdmission(quorum=2)
                gate.local_emergency_stop()
                self.assertIs(gate.local_reset(operator_confirmed=untrusted), False)
                self.assertFalse(gate.admit(observation("a")))
                self.assertTrue(gate.local_reset(operator_confirmed=True))

    def test_boolean_configuration_rejected(self):
        for key in ("quorum", "window", "max_buckets", "max_nonces"):
            with self.subTest(key=key):
                kwargs = dict(quorum=2, window=1, max_buckets=128, max_nonces=1024)
                kwargs[key] = True
                with self.assertRaises(ValueError):
                    EpochAdmission(**kwargs)

    def test_durable_reset_rejects_nonboolean_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "admission.sqlite")
            gate = DurableEpochAdmission(path, quorum=2)
            gate.local_emergency_stop()
            self.assertFalse(gate.local_reset(operator_confirmed="true"))
            restarted = DurableEpochAdmission(path, quorum=2)
            self.assertFalse(restarted.admit(observation("a")))
            self.assertTrue(restarted.local_reset(operator_confirmed=True))
            self.assertFalse(restarted.admit(observation("a")))
            self.assertTrue(restarted.admit(observation("b")))


if __name__ == "__main__":
    unittest.main()
