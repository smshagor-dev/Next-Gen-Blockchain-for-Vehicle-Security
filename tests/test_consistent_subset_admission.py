"""Research-only consistent-subset admission property regressions.

These are deterministic scripted protocol tests, NOT measurements of vehicle
safety, real physical event truth or original scientific superiority.
"""
import hashlib
import itertools
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from experiments.v2x.consistent_subset_admission import ConsistentSubsetAdmissionGate

UTC = datetime(2026, 1, 1, tzinfo=timezone.utc)


def evidence(id="event1", lat=51.5, kind="ROAD_HAZARD", observed=UTC, source="digest1"):
    return {"evidence": {
        "incident_id": id, "event_class": kind,
        "observed_at": observed.isoformat(), "lat": lat,
        "lon": -0.1, "sensor_sha256": hashlib.sha256(source.encode()).hexdigest(),
    }}


class ConsistentSubsetGateTests(unittest.TestCase):
    def setUp(self):
        self.mono = 0.0
        self.now = UTC

    def gate(self, **kwargs):
        return ConsistentSubsetAdmissionGate(
            clock=lambda: self.mono, utc_clock=lambda: self.now, **kwargs
        )

    def test_honest_subquorum_survives_first_compromised_location(self):
        gate = self.gate()
        self.assertEqual(
            gate.evaluate(authenticated_sender_id="MALICIOUS_A",
                          payload=evidence(lat=51.5067, source="bad")).status,
            "pending",
        )
        self.assertEqual(
            gate.evaluate(authenticated_sender_id="HONEST_A",
                          payload=evidence(source="good1")).status,
            "pending",
        )
        accepted = gate.evaluate(
            authenticated_sender_id="HONEST_B",
            payload=evidence(lat=51.50005, source="good2"),
        )
        self.assertTrue(accepted.relayed)
        self.assertEqual(
            gate.accepted_sources_for("event1"), ("HONEST_A", "HONEST_B")
        )
        self.assertNotIn("MALICIOUS_A", gate.accepted_sources_for("event1"))

    def test_consistent_honest_subset_order_invariant_under_cap(self):
        expected = {"HONEST_A", "HONEST_B"}
        reports = (
            ("MALICIOUS_A", evidence(lat=51.5067, source="bad")),
            ("HONEST_A", evidence(source="good1")),
            ("HONEST_B", evidence(lat=51.50005, source="good2")),
        )
        for permutation in itertools.permutations(reports):
            gate = self.gate()
            outputs = [
                gate.evaluate(authenticated_sender_id=source, payload=payload)
                for source, payload in permutation
            ]
            self.assertEqual(sum(r.relayed for r in outputs), 1)
            self.assertEqual(set(gate.accepted_sources_for("event1")), expected)

    def test_two_colluding_enrolled_sources_remain_a_known_vulnerability(self):
        gate = self.gate()
        gate.evaluate(authenticated_sender_id="BAD_A", payload=evidence(source="bad1"))
        accepted = gate.evaluate(
            authenticated_sender_id="BAD_B", payload=evidence(source="bad2")
        )
        self.assertTrue(accepted.relayed)
        self.assertEqual(set(gate.accepted_sources_for("event1")), {"BAD_A", "BAD_B"})

    def test_copy_digest_and_same_source_can_never_double_vote(self):
        gate = self.gate()
        gate.evaluate(authenticated_sender_id="NODE_A", payload=evidence(source="one"))
        same = gate.evaluate(authenticated_sender_id="NODE_A", payload=evidence(source="two"))
        copied = gate.evaluate(authenticated_sender_id="NODE_B", payload=evidence(source="one"))
        self.assertEqual(same.reason, "REPEATED_IDENTITY")
        self.assertEqual(copied.reason, "DUPLICATE_SENSOR_DIGEST")
        self.assertFalse(same.relayed or copied.relayed)
        self.assertEqual(gate.snapshot()["pending"], 1)

    def test_all_pairs_must_match_for_three_way_quorum(self):
        gate = self.gate(quorum=3)
        gate.evaluate(authenticated_sender_id="NODE_A", payload=evidence(lat=51.5, source="one"))
        gate.evaluate(authenticated_sender_id="NODE_B", payload=evidence(lat=51.5005, source="two"))
        out = gate.evaluate(
            authenticated_sender_id="NODE_C",
            payload=evidence(lat=51.5010, source="three"),
        )
        self.assertEqual(out.status, "pending")  # first-last >=100m
        self.assertEqual(gate.accepted_sources_for("event1"), ())

    def test_missing_reporter_and_delayed_corrob_are_not_safety_proven(self):
        gate = self.gate()
        only = gate.evaluate(authenticated_sender_id="NODE_A", payload=evidence(source="a"))
        self.assertEqual(only.status, "pending")
        self.assertFalse(only.relayed)
        self.now += timedelta(seconds=9)
        self.mono += 9
        late = gate.evaluate(
            authenticated_sender_id="NODE_B",
            payload=evidence(observed=self.now, source="b"),
        )
        self.assertEqual(late.status, "pending")  # two event times are 9s apart
        self.assertFalse(late.relayed)

    def test_bounded_pool_flooding_still_denies_later_honest_sources(self):
        gate = self.gate(max_reports=3)
        for i in range(3):
            out = gate.evaluate(
                authenticated_sender_id=f"BAD{i}",
                payload=evidence(lat=51.5 + i * 0.01, source=f"bad{i}")
            )
            self.assertEqual(out.status, "pending")
        blocked = gate.evaluate(
            authenticated_sender_id="HONEST_A",
            payload=evidence(lat=51.5, source="honest")
        )
        self.assertEqual(blocked.reason, "INCIDENT_REPORT_CAPACITY_REACHED")
        self.assertEqual(gate.snapshot()["active_incidents"], 1)

    def test_capacity_and_expiry_allow_new_incidents_without_unbounded_state(self):
        gate = self.gate(max_incidents=1, incident_ttl_sec=5)
        gate.evaluate(authenticated_sender_id="NODE_A", payload=evidence(id="a", source="1"))
        reject = gate.evaluate(authenticated_sender_id="NODE_B", payload=evidence(id="b", source="2"))
        self.assertEqual(reject.reason, "INCIDENT_CAPACITY_REACHED")
        self.assertEqual(gate.snapshot()["active_incidents"], 1)
        self.mono += 6
        self.now += timedelta(seconds=6)
        granted = gate.evaluate(
            authenticated_sender_id="NODE_B",
            payload=evidence(id="b", observed=self.now, source="3")
        )
        self.assertEqual(granted.status, "pending")
        self.assertEqual(gate.snapshot()["active_incidents"], 1)

    def test_malformed_remote_action_fails_before_vote(self):
        gate = self.gate()
        payload = evidence()
        payload["remote_brake_pressure"] = 100
        rejected = gate.evaluate(authenticated_sender_id="NODE_A", payload=payload)
        self.assertEqual(rejected.reason, "UNEXPECTED_EVIDENCE_FIELDS")
        self.assertEqual(gate.snapshot()["active_incidents"], 0)

    def test_quorum_and_resource_configuration_limits(self):
        for options in (
            {"quorum": 1}, {"quorum": 5}, {"max_reports": 1},
            {"max_reports": 17}, {"max_incidents": 0},
            {"incident_ttl_sec": 0}, {"max_distance_m": float("nan")},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.gate(**options)


if __name__ == "__main__":
    unittest.main()
