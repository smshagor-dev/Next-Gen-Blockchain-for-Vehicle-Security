"""POSIX subprocess SIGKILL fault campaign for issuer persistence boundaries.

Synthetic hashes; this is a filesystem correctness control, NOT blockchain finality
or evidence of physical power-loss durability. Each trial uses a fresh directory.
"""
import hashlib
import multiprocessing as mp
import os
import tempfile
import unittest
from pathlib import Path

from research_contracts.independent_checkpoint_issuer import (
    CheckpointRefused, IndependentCheckpointIssuer,
)

KEY = b"simulation-only-issuer-key-32bytes-long"
VEHICLE = "fault-campaign-vehicle"


def _hash(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


BASE = [_hash("genesis"), _hash("one")]
EXTENDED = BASE + [_hash("two")]


def _kill_at_boundary(directory, boundary, queue):
    """Child dies inside the real persistence path; no fake exceptions."""
    issuer = IndependentCheckpointIssuer(directory, VEHICLE, KEY)
    original_fsync = os.fsync
    original_replace = os.replace
    count = 0

    def injected_fsync(fd):
        nonlocal count
        count += 1
        # First fsync is the pending file, second is parent directory.
        if boundary == "before_file_fsync" and count == 1:
            os.kill(os.getpid(), 9)
        if boundary == "before_directory_fsync" and count == 2:
            os.kill(os.getpid(), 9)
        return original_fsync(fd)

    def injected_replace(src, dst):
        if boundary == "before_replace":
            os.kill(os.getpid(), 9)
        result = original_replace(src, dst)
        if boundary == "after_replace":
            os.kill(os.getpid(), 9)
        return result

    os.fsync = injected_fsync
    os.replace = injected_replace
    queue.put("entered")
    issuer.issue(EXTENDED)
    queue.put("unexpected-return")


@unittest.skipUnless(os.name == "posix", "SIGKILL and flock require POSIX")
class IssuerCrashBoundaryTests(unittest.TestCase):
    def test_sigkill_at_four_persistence_boundaries(self):
        ctx = mp.get_context("spawn")
        for boundary in (
            "before_file_fsync", "before_replace",
            "after_replace", "before_directory_fsync",
        ):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as d:
                issuer = IndependentCheckpointIssuer(d, VEHICLE, KEY)
                initial = issuer.issue(BASE)
                queue = ctx.Queue()
                proc = ctx.Process(target=_kill_at_boundary, args=(d, boundary, queue))
                proc.start()
                self.assertEqual(queue.get(timeout=10), "entered")
                proc.join(timeout=10)
                if proc.is_alive():
                    proc.kill()
                    proc.join(timeout=5)
                    self.fail("child did not reach kill boundary")
                self.assertEqual(proc.exitcode, -9)
                restarted = IndependentCheckpointIssuer(d, VEHICLE, KEY)
                observed = restarted._load()
                # Before replace the old state is authoritative; after replace
                # the new state is visible, though power-loss durability is unknown.
                expected = BASE if boundary in (
                    "before_file_fsync", "before_replace"
                ) else EXTENDED
                self.assertEqual(observed["pins"], expected)
                self.assertEqual(observed["revision"],
                                 initial["revision"] + (expected == EXTENDED))
                # Stale pending cleanup must not bypass pinned prefix.
                with self.assertRaisesRegex(CheckpointRefused, "truncation"):
                    restarted.issue(BASE[:1])
                receipt = restarted.issue(EXTENDED)
                self.assertEqual(receipt["height"], 3)
                self.assertFalse(restarted.path.with_suffix(".pending").exists())


if __name__ == "__main__":
    unittest.main()
