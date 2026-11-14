"""Synthetic protocol tests only; no genuine VeReMi/CAN incident measurements."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from replay_external_incidents import EVENT_COLUMNS, replay

WORLD = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "ground_truth")
GROUP = ("exp", "urban", "73", "test")
START = "2026-01-01T00:00:00Z"
END = "2026-01-01T00:01:00Z"


def encode(header, rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue().encode()


def event(seq, incident, sender, nonce, second, verified="1",
          lat="52.0", lon="13.0", observed=None, digest=None):
    return (*GROUP, str(seq), f"2026-01-01T00:00:{second:02d}Z",
            verified, sender, nonce, incident, "ROAD_HAZARD",
            observed or f"2026-01-01T00:00:{second:02d}Z", lat, lon,
            digest or hashlib.sha256(nonce.encode()).hexdigest())


class LabelIsolatedReplayTests(unittest.TestCase):
    def setUp(self):
        self.world = encode(WORLD, [
            (*GROUP, "hazard", "1"), (*GROUP, "quiet", "0"),
            (*GROUP, "partitioned", "1"), (*GROUP, "collusion", "0")])
        self.events = encode(EVENT_COLUMNS, [
            event(0, "hazard", "honest-A", "a", 1),
            event(1, "hazard", "honest-B", "b", 3),
            event(2, "collusion", "liar-A", "c", 5),
            event(3, "collusion", "liar-B", "d", 6),
        ])

    def score(self, *, world=None, events=None, world_pin=None, events_pin=None, **kwargs):
        w = self.world if world is None else world
        e = self.events if events is None else events
        return replay(w, e,
                      pinned_world_sha256=world_pin or hashlib.sha256(w).hexdigest(),
                      pinned_events_sha256=events_pin or hashlib.sha256(e).hexdigest(),
                      expected_group=GROUP, window_start=START, window_end=END, **kwargs)

    def test_actual_quorum_and_auth_only_on_same_world_universe(self):
        r = self.score()
        self.assertEqual(r["independent_world_incidents"], 4)
        self.assertEqual(r["methods"]["authenticated_only"]["tp"], 1)
        self.assertEqual(r["methods"]["authenticated_only"]["fn"], 1)
        self.assertEqual(r["methods"]["authenticated_only"]["fp"], 1)
        self.assertEqual(r["methods"]["authenticated_only"]["tn"], 1)
        self.assertEqual(r["methods"]["evidence_quorum_2"]["relayed_incidents"],
                         ["collusion", "hazard"])
        self.assertEqual(r["methods"]["ablation_quorum_3"]["relayed_incidents"], [])
        self.assertEqual(r["methods"]["ablation_quorum_3"]["fn"], 2)
        self.assertEqual(r["methods"]["ablation_quorum_3"]["tn"], 2)
        self.assertEqual(r["methods"]["evidence_quorum_2"]
                         ["delay_from_first_valid_received_ms"]["mean"], 2000)
        self.assertFalse(r["publication_ready"])

    def test_zero_observation_outage_cannot_disappear(self):
        r = self.score(events=encode(EVENT_COLUMNS, []))
        for metrics in r["methods"].values():
            self.assertEqual((metrics["tp"], metrics["fn"], metrics["fp"], metrics["tn"]),
                             (0, 2, 0, 2))
        self.assertEqual(r["event_admission_counters"]["events"], 0)

    def test_replayed_nonce_not_additional_independent_vote(self):
        events = encode(EVENT_COLUMNS, [
            event(0, "hazard", "a", "same", 1),
            event(1, "hazard", "a", "same", 2),
        ])
        r = self.score(events=events)
        self.assertEqual(r["event_admission_counters"]["replayed_nonce_rejected"], 1)
        self.assertEqual(r["methods"]["evidence_quorum_2"]["tp"], 0)
        self.assertIn("rejected_replayed_nonce", r["decisions"][1]["authenticated_only"])

    def test_unverified_hub_flag_not_counted_even_when_spoofed(self):
        events = encode(EVENT_COLUMNS, [
            event(0, "hazard", "a", "a", 1, verified="0"),
            event(1, "hazard", "b", "b", 2, verified="1"),
        ])
        r = self.score(events=events)
        self.assertEqual(r["methods"]["authenticated_only"]["tp"], 1)
        self.assertEqual(r["methods"]["evidence_quorum_2"]["tp"], 0)
        self.assertEqual(r["event_admission_counters"]["asserted_unverified"], 1)

    def test_bad_digest_is_rejected_before_all_methods(self):
        e = encode(EVENT_COLUMNS, [event(0, "hazard", "a", "a", 1, digest="0")])
        r = self.score(events=e)
        self.assertEqual(r["event_admission_counters"]["invalid_evidence_rejected"], 1)
        for m in r["methods"].values():
            self.assertEqual(m["tp"], 0)

    def test_stale_observation_is_rejected(self):
        e = encode(EVENT_COLUMNS, [event(
            0, "hazard", "a", "a", 30, observed="2026-01-01T00:00:00Z")])
        r = self.score(events=e)
        self.assertEqual(r["event_admission_counters"]["invalid_evidence_rejected"], 1)

    def test_location_conflict_is_rejected_by_gates_not_auth_only(self):
        e = encode(EVENT_COLUMNS, [
            event(0, "hazard", "a", "a", 1, lat="52.0"),
            event(1, "hazard", "b", "b", 2, lat="52.001"),
        ])
        r = self.score(events=e)
        self.assertEqual(r["methods"]["authenticated_only"]["tp"], 1)
        self.assertEqual(r["methods"]["evidence_quorum_2"]["tp"], 0)
        self.assertEqual(r["methods"]["ablation_radius_10km"]["tp"], 1)

    def test_wrong_world_hash_rejected(self):
        with self.assertRaisesRegex(ValueError, "source SHA"):
            self.score(world_pin="0" * 64)

    def test_wrong_trace_hash_rejected(self):
        with self.assertRaisesRegex(ValueError, "source SHA"):
            self.score(events_pin="0" * 64)

    def test_unlabelled_event_must_have_independent_world_opportunity(self):
        e = encode(EVENT_COLUMNS, [event(0, "unknown", "a", "a", 1)])
        with self.assertRaisesRegex(ValueError, "absent from independent world"):
            self.score(events=e)

    def test_labels_must_not_be_present_in_event_trace(self):
        e = encode((*EVENT_COLUMNS, "ground_truth"), [
            (*event(0, "hazard", "a", "a", 1), "1")])
        with self.assertRaisesRegex(ValueError, "label-free"):
            self.score(events=e)

    def test_duplicate_world_opportunities_rejected(self):
        w = encode(WORLD, [(*GROUP, "same", "1"), (*GROUP, "same", "0")])
        with self.assertRaisesRegex(ValueError, "duplicate world"):
            self.score(world=w)

    def test_mixed_split_rejected(self):
        e = encode(EVENT_COLUMNS, [
            (*event(0, "hazard", "a", "a", 1)[:3], "train",
             *event(0, "hazard", "a", "a", 1)[4:]),
        ])
        with self.assertRaisesRegex(ValueError, "mixed scenario"):
            self.score(events=e)

    def test_nonchronological_and_duplicate_sequence_rejected(self):
        earlier = encode(EVENT_COLUMNS, [
            event(0, "hazard", "a", "a", 3), event(1, "hazard", "b", "b", 1)])
        with self.assertRaisesRegex(ValueError, "nonchronological"):
            self.score(events=earlier)
        duplicate = encode(EVENT_COLUMNS, [
            event(1, "hazard", "a", "a", 1), event(1, "hazard", "b", "b", 3)])
        with self.assertRaisesRegex(ValueError, "event sequence"):
            self.score(events=duplicate)

    def test_window_exceeded_rejected(self):
        e = encode(EVENT_COLUMNS, [
            (*event(0, "hazard", "a", "a", 1)[:5],
             "2026-01-01T00:01:00Z",
             *event(0, "hazard", "a", "a", 1)[6:]),
        ])
        with self.assertRaisesRegex(ValueError, "outside experiment window"):
            self.score(events=e)

    def test_finite_capacity_applied_to_real_gate(self):
        e = encode(EVENT_COLUMNS, [
            event(0, "hazard", "a", "a", 1),
            event(1, "collusion", "b", "b", 2),
        ])
        r = self.score(events=e, max_incidents=1)
        self.assertEqual(r["methods"]["authenticated_only"]["tp"], 1)
        self.assertEqual(r["methods"]["evidence_quorum_2"]["tp"], 0)
        self.assertIn("INCIDENT_CAPACITY_REACHED",
                      r["decisions"][1]["evidence_quorum_2"])
        self.assertLessEqual(r["resource_observations"]
                             ["maximum_active_incident_states"]["evidence_quorum_2"], 1)

    def test_cli_executes_actual_policy_and_emits_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            w, e, out = root / "world.csv", root / "events.csv", root / "result.json"
            w.write_bytes(self.world)
            e.write_bytes(self.events)
            cmd = [sys.executable, str(Path(__file__).with_name("replay_external_incidents.py")),
                   "--world", str(w), "--events", str(e),
                   "--world-sha256", hashlib.sha256(self.world).hexdigest(),
                   "--events-sha256", hashlib.sha256(self.events).hexdigest(),
                   "--experiment-id", GROUP[0], "--scenario-id", GROUP[1],
                   "--seed", GROUP[2], "--split", GROUP[3],
                   "--window-start", START, "--window-end", END,
                   "--output", str(out)]
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).parent.parent.parent)
                       + os.pathsep + str(Path(__file__).parent))
            p = subprocess.run(cmd, env=env, text=True, capture_output=True, check=True)
            result = json.loads(out.read_text())
            self.assertEqual(result["methods"]["ablation_quorum_3"]["fn"], 2)
            self.assertEqual(json.loads(p.stdout)["result_sha256"],
                             hashlib.sha256(out.read_bytes()).hexdigest())
            self.assertFalse(result["publication_ready"])


if __name__ == "__main__":
    unittest.main()
