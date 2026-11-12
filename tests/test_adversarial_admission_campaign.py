"""Software threat-model contract tests, not real independent V2X experiments."""
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from experiments.v2x.adversarial_admission_campaign import (
    METHODS, SCENARIOS, evaluate_trace, make_trace, run_campaign,
)
from v2x_evidence_admission import EvidenceAdmissionGate


class AdversarialAdmissionCampaignTests(unittest.TestCase):
    def test_policy_exercised_with_expected_failures_and_baseline(self):
        trial = evaluate_trace(make_trace(13))
        self.assertEqual(len(SCENARIOS), 13)
        m = trial["methods"]
        self.assertEqual((m["authenticated_only"]["tp_incidents"], m["authenticated_only"]["fp_incidents"]), (6, 6))
        self.assertEqual((m["quorum_two"]["tp_incidents"], m["quorum_two"]["fp_incidents"]), (2, 1))
        self.assertEqual((m["quorum_three"]["tp_incidents"], m["quorum_three"]["fp_incidents"]), (1, 0))
        self.assertEqual((m["wide_radius"]["tp_incidents"], m["wide_radius"]["fp_incidents"]), (4, 2))
        self.assertGreater(m["quorum_two"]["mean_time_to_forward_ms"], 0)
        self.assertEqual(m["authenticated_only"]["mean_time_to_forward_ms"], 0)
        self.assertEqual(sum(m["quorum_two"][x] for x in ("tp_incidents","fp_incidents","tn_incidents","fn_incidents")), len(SCENARIOS))
        self.assertEqual(m["quorum_two"]["legitimate_delivery_rate"], 2 / 6)
        self.assertEqual(m["quorum_two"]["false_acceptance_rate"], 1 / 7)

    def test_single_enrolled_forgery_and_duplicate_source_do_not_pass_quorum(self):
        accepted = evaluate_trace(make_trace(2))["accepted_by_scenario"]
        self.assertIn("false_single_enrolled", accepted["authenticated_only"])
        self.assertIn("false_repeated_identity", accepted["authenticated_only"])
        self.assertNotIn("false_single_enrolled", accepted["quorum_two"])
        self.assertNotIn("false_repeated_identity", accepted["quorum_two"])
        self.assertNotIn("false_copied_digest", accepted["quorum_two"])

    def test_two_colluding_enrolled_identities_can_defeat_quorum(self):
        accepted = evaluate_trace(make_trace(3))["accepted_by_scenario"]
        self.assertIn("false_colluding_enrolled", accepted["quorum_two"])
        self.assertNotIn("false_colluding_enrolled", accepted["quorum_three"])
        self.assertIn("false_colluding_enrolled", accepted["wide_radius"])

    def test_attacker_first_wins_incident_key_can_suppress_honest_quorum(self):
        trial = evaluate_trace(make_trace(19))
        accepted = trial["accepted_by_scenario"]
        # Same true real-world incident in the script, but malicious enrolled
        # report seeds incorrect geolocation first, causing honest reporters
        # to be rejected by the strict admission gate.
        self.assertIn("true_incident_id_preemption", accepted["authenticated_only"])
        self.assertNotIn("true_incident_id_preemption", accepted["quorum_two"])
        self.assertNotIn("true_incident_id_preemption", accepted["quorum_three"])
        # Wide radius accepts that incident with one compromised quorum vote.
        self.assertIn("true_incident_id_preemption", accepted["wide_radius"])
        roles = trial["accepted_voter_roles"]["wide_radius"]["true_incident_id_preemption"]
        self.assertIn("malicious", roles)
        self.assertIn("nonmalicious_scripted", roles)
        self.assertEqual(trial["methods"]["quorum_two"]["malicious_assisted_admitted_incidents"], 1)
        self.assertEqual(trial["methods"]["wide_radius"]["malicious_assisted_admitted_incidents"], 3)

    def test_partitioned_honest_incidents_are_delayed_or_suppressed(self):
        accepted = evaluate_trace(make_trace(4))["accepted_by_scenario"]
        self.assertIn("true_partitioned", accepted["authenticated_only"])
        for method in ("quorum_two","quorum_three","wide_radius"):
            self.assertNotIn("true_partitioned", accepted[method])
        self.assertNotIn("true_temporal_gap", accepted["quorum_two"])
        self.assertIn("true_displaced_observers", accepted["wide_radius"])
        self.assertNotIn("true_displaced_observers", accepted["quorum_two"])

    def test_transport_unverified_and_remote_action_field_never_gain_quorum(self):
        trial = evaluate_trace(make_trace(5))
        decisions = trial["decisions"]
        forged = [r for r in decisions if r["scenario"] == "false_unverified_transport"][0]
        self.assertEqual(forged["authenticated_only"], "unverified_not_forwarded")
        self.assertEqual(forged["quorum_two"], "unverified_not_forwarded")
        action = [r for r in decisions if r["scenario"] == "false_signed_action_field"][0]
        self.assertEqual(action["quorum_two"], "rejected:UNEXPECTED_EVIDENCE_FIELDS")
        self.assertNotIn("false_signed_action_field", trial["accepted_by_scenario"]["quorum_two"])

    def test_trace_time_and_source_truth_validation_fail_closed(self):
        trace = make_trace(6)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            evaluate_trace([])
        with self.assertRaisesRegex(ValueError, "times must be nondecreasing"):
            evaluate_trace(list(reversed(trace)))
        another = make_trace(7)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            evaluate_trace(trace + another)

    def test_rerun_same_seeds_produces_identical_sha_bounded_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = run_campaign(root / "first", seeds=(3, 8, 21))
            second = run_campaign(root / "second", seeds=(3, 8, 21))
            self.assertEqual(first, second)
            for name in ("synthetic_adversarial_campaign.json", "synthetic_adversarial_decisions.csv",
                         "synthetic_campaign_manifest.json"):
                a = (root / "first" / name).read_bytes()
                b = (root / "second" / name).read_bytes()
                self.assertEqual(a, b)
            manifest = json.loads((root / "first/synthetic_campaign_manifest.json").read_text())
            self.assertEqual(
                manifest["results_sha256"],
                hashlib.sha256((root / "first/synthetic_adversarial_campaign.json").read_bytes()).hexdigest(),
            )
            self.assertFalse(first["publication_ready"])
            self.assertFalse(first["statistical_significance"])
            self.assertEqual(first["independent_empirical_runs"], 0)
            self.assertEqual(len(first["per_seed"]), 3)
            self.assertTrue(all(set(row["methods"]) == set(METHODS) for row in first["per_seed"]))

    def test_seed_variation_is_repeatable_not_independent_empirical_data(self):
        a = make_trace(0)
        b = make_trace(1)
        self.assertNotEqual(
            [x.received_ms for x in a], [x.received_ms for x in b],
        )
        self.assertEqual(
            [x.scenario for x in a], [x.scenario for x in b],
        )
        self.assertEqual(
            evaluate_trace(a)["methods"]["quorum_two"]["tp_incidents"],
            evaluate_trace(b)["methods"]["quorum_two"]["tp_incidents"],
        )

    def test_seed_validation_rejects_duplicates_invalid_and_unbounded_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            for seeds in ((), (1, 1), (-1,), (True,), tuple(range(101))):
                with self.subTest(seeds=str(seeds)[:40]), self.assertRaises(ValueError):
                    run_campaign(Path(tmp) / "result", seeds=seeds)

    def test_gate_rejects_incident_capacity_exhaustion_and_recovers_after_ttl(self):
        now = {"m": 0.0, "utc": datetime(2026, 1, 1, tzinfo=timezone.utc)}
        gate = EvidenceAdmissionGate(
            max_incidents=4, incident_ttl_sec=20,
            clock=lambda: now["m"], utc_clock=lambda: now["utc"],
        )
        def payload(index):
            return {"evidence": {
                "incident_id": f"incident-{index}", "event_class": "ROAD_HAZARD",
                "observed_at": now["utc"].isoformat(), "lat": 51.5, "lon": -0.1,
                "sensor_sha256": hashlib.sha256(str(index).encode()).hexdigest(),
            }}
        for i in range(4):
            self.assertEqual(gate.evaluate(authenticated_sender_id=f"NODE{i}", payload=payload(i)).status, "pending")
        denied = gate.evaluate(authenticated_sender_id="NODE4", payload=payload(4))
        self.assertEqual(denied.reason, "INCIDENT_CAPACITY_REACHED")
        self.assertEqual(gate.snapshot()["active_incidents"], 4)
        now["m"] += 21
        now["utc"] += timedelta(seconds=21)
        granted = gate.evaluate(authenticated_sender_id="NODE4", payload=payload(4))
        self.assertEqual(granted.status, "pending")
        self.assertEqual(gate.snapshot()["active_incidents"], 1)


if __name__ == "__main__":
    unittest.main()
