import unittest
from experiments.claim_validation.heldout_runner import load_schedule, worker_input, adjudicate, run_case


class HeldoutScheduleTests(unittest.TestCase):
    def test_frozen_schedule_counts_and_no_truth_leak(self):
        cases = load_schedule()
        self.assertEqual(len(cases), 82)
        self.assertEqual(len({x["cell"] + x["domain"] for x in cases}), 41)
        for case in cases:
            self.assertFalse(any(k.startswith("expected") for k in worker_input(case)))

    def test_actual_subprocess_consensus_controls(self):
        cases = [c for c in load_schedule() if c["domain"] == "consensus" and c["n"] == 4
                 and c["num"] == 1 and c["replicate"] == 0]
        for case in cases:
            with self.subTest(case=case["id"]):
                result = run_case(case)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["output"]["gate"]["eligibility"] == "ELIGIBLE", case["expected"])

    def test_reference_disagreement_detected(self):
        case = next(c for c in load_schedule() if c["domain"] == "identity" and c["expected"])
        self.assertFalse(adjudicate(case, {"ack": False, "bound": False, "registry_size": case["size"],
                                           "registry_member": True}))


if __name__ == "__main__":
    unittest.main()
