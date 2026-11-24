"""Actual Go-hash negative controls for process restart and service generation.

Non-actuating synthetic blocks, generated using the documented Go serialization.
These are protocol correctness controls, not real consensus or research effectiveness.
"""
import hashlib
import unittest

from ledger_integrity import (
    GoLedgerSnapshotVerifier, LedgerIntegrityError, go_telemetry_string,
    verify_go_block,
)
from research_contracts.go_generation_rollback_control import CrossGenerationPrefixMonitor


def sha2(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha3(s):
    return hashlib.sha3_256(s.encode("utf-8")).hexdigest()


def valid_chain(events):
    chain = []
    previous = "0"
    for index, event in enumerate(events):
        telemetry = {"timestamp": "synthetic"}
        timestamp = f"synthetic-{index}"
        tel = go_telemetry_string(telemetry)
        tel2, tel3 = sha2(tel), sha3(tel)
        event2, event3 = sha2(event), sha3(event)
        block_hash = sha3(f"{index}{timestamp}v{tel3}{event3}{previous}")
        block = {
            "index": index, "timestamp": timestamp, "vehicle_id": "v",
            "previous_hash": previous, "telemetry": telemetry,
            "event_data": event, "telemetry_hash_sha2": tel2,
            "telemetry_hash_sha3": tel3, "event_hash_sha2": event2,
            "event_hash_sha3": event3, "block_hash": block_hash,
            "dual_hash_combined": sha2(block_hash) + ":" + sha3(block_hash),
        }
        verify_go_block(block, previous if index else None, "v", index)
        chain.append(block)
        previous = block_hash
    return chain


class RealHashRollbackControls(unittest.TestCase):
    def test_cross_generation_monitor_rejects_valid_shorter_chain(self):
        chain = valid_chain(["event-A", "event-B"])
        monitor = CrossGenerationPrefixMonitor("v")
        self.assertTrue(monitor.verify(chain, "instance-A"))
        with self.assertRaisesRegex(LedgerIntegrityError, "truncation"):
            monitor.verify(chain[:1], "instance-B")

    def test_process_restart_accepts_valid_truncation_without_external_anchor(self):
        chain = valid_chain(["event-A", "event-B"])
        old = CrossGenerationPrefixMonitor("v")
        old.verify(chain, "instance-A")
        restarted = CrossGenerationPrefixMonitor("v")
        # Demonstrates the limit: in-memory history cannot survive restart.
        self.assertTrue(restarted.verify(chain[:1], "instance-B"))
        self.assertEqual(restarted.observed_blocks, 1)

    def test_valid_rewrite_on_generation_change_is_detected_locally(self):
        original = valid_chain(["event-A", "event-B"])
        rewritten = valid_chain(["event-A", "attacker-alternative"])
        monitor = CrossGenerationPrefixMonitor("v")
        monitor.verify(original, "instance-A")
        with self.assertRaisesRegex(LedgerIntegrityError, "prefix mutation"):
            monitor.verify(rewritten, "instance-B")

    def test_fresh_verifier_accepts_valid_rewritten_history(self):
        original = valid_chain(["event-A", "event-B"])
        rewritten = valid_chain(["event-A", "attacker-alternative"])
        first = GoLedgerSnapshotVerifier("v")
        self.assertTrue(first.verify_and_track(original, "instance-A"))
        # A new observer has no authenticated checkpoint of the earlier tip.
        self.assertTrue(GoLedgerSnapshotVerifier("v").verify_and_track(
            rewritten, "instance-B"
        ))


if __name__ == "__main__":
    unittest.main()
