"""Synthetic contract tests only; not real V2X research measurements."""
import csv
import hashlib
import hmac
import io
import unittest
from join_world_incidents import evaluate

WORLD = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "ground_truth")
CAP = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "node_id", "nonce", "received_at", "session_verified", "alert_relayed")


def csv_bytes(headers, rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue().encode()


class WorldJoinTests(unittest.TestCase):
    def setUp(self):
        self.world = csv_bytes(WORLD, [
            ("exp", "scenario", "1", "test", "hazard", "1"),
            ("exp", "scenario", "1", "test", "quiet", "0"),
            ("exp", "scenario", "1", "test", "missing", "1")])
        self.capture = csv_bytes(CAP, [
            ("exp", "scenario", "1", "test", "hazard", "nodeA", "nonceA", "2026-01-01T00:00:00Z", "1", "1")])
        self.key = b"synthetic-test-key"

    def check(self, world=None, capture=None, receipt=None, world_digest=None, capture_digest=None):
        world = self.world if world is None else world
        capture = self.capture if capture is None else capture
        receipt = receipt or {"capture_sha256": hashlib.sha256(capture).hexdigest(),
                             "hmac_sha256": hmac.new(self.key, capture, hashlib.sha256).hexdigest()}
        return evaluate(world, capture, receipt, self.key,
                        world_digest or hashlib.sha256(world).hexdigest(),
                        capture_digest or hashlib.sha256(capture).hexdigest())

    def test_unobserved_positive_is_false_negative(self):
        result = self.check()
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (1, 0, 1, 1))
        self.assertEqual(result["unobserved_positive_incidents"], 1)
        self.assertFalse(result["publication_ready"])

    def test_pinned_world_tamper(self):
        with self.assertRaisesRegex(ValueError, "operator-pinned"):
            self.check(world_digest="0" * 64)

    def test_forged_receipt(self):
        receipt = {"capture_sha256": hashlib.sha256(self.capture).hexdigest(),
                   "hmac_sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "HMAC"):
            self.check(receipt=receipt)

    def test_unknown_incident(self):
        capture = self.capture.replace(b"hazard,nodeA", b"otherx,nodeA")
        with self.assertRaisesRegex(ValueError, "without matching"):
            self.check(capture=capture)

    def test_replayed_nonce(self):
        lines = self.capture.decode().splitlines()
        capture = ("\n".join(lines + [lines[1]]) + "\n").encode()
        with self.assertRaisesRegex(ValueError, "replayed"):
            self.check(capture=capture)

    def test_injected_attacker_label(self):
        world = self.world.replace(b"ground_truth", b"attacker")
        with self.assertRaisesRegex(ValueError, "columns"):
            self.check(world=world)

    def test_unverified_relay(self):
        capture = self.capture.replace(b",1,1\r\n", b",0,1\r\n")
        with self.assertRaisesRegex(ValueError, "unverified relay"):
            self.check(capture=capture)


if __name__ == "__main__":
    unittest.main()
