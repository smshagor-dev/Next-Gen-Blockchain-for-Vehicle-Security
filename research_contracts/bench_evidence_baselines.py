"""Synthetic paired incident experiment. Not real-world V2X evidence."""
import argparse
import csv
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from v2x_evidence_gate import Observation, admit_hazard


def experiment(seed=17, trials=1000, *, witnesses=4, compromised_devices=1):
    if trials < 2 or witnesses < 2 or not 0 <= compromised_devices <= witnesses:
        raise ValueError("invalid experiment parameters")
    rng = random.Random(seed)
    records = []
    for trial in range(trials):
        truth = bool(rng.getrandbits(1))
        malicious = set(rng.sample(range(witnesses), compromised_devices))
        # Group assignment is fixed before generating reports; target and one
        # witness share a correlated failure domain.
        groups = ["A", "A"] + [f"G{i}" for i in range(2, witnesses)]
        observations = tuple(
            Observation(f"device-{i}", groups[i], f"incident-{trial}", 100.,
                        not truth if i in malicious else truth, True)
            for i in range(witnesses)
        )
        target = observations[0]
        decisions = {
            "authentication_only": target.authenticated and target.hazard,
            "sender_count_quorum": sum(o.authenticated and o.hazard for o in observations) >= 2,
            "independent_group_gate": admit_hazard(target, observations[1:], now=101.).admitted,
        }
        for policy, accepted in decisions.items():
            records.append({
                "seed": seed, "incident": trial, "truth_hazard": int(truth),
                "compromised_devices_requested": compromised_devices,
                "policy": policy, "admitted": int(accepted),
                "false_admission": int(accepted and not truth),
                "missed_hazard": int(not accepted and truth),
            })
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--trials", type=int, default=1000)
    parser.add_argument("--witnesses", type=int, default=4)
    parser.add_argument("--compromised-devices", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = experiment(args.seed, args.trials, witnesses=args.witnesses,
                      compromised_devices=args.compromised_devices)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for policy in ("authentication_only", "sender_count_quorum", "independent_group_gate"):
        subset = [r for r in rows if r["policy"] == policy]
        print(policy, "false_admissions=", sum(r["false_admission"] for r in subset),
              "missed_hazards=", sum(r["missed_hazard"] for r in subset),
              "incidents=", len(subset))


if __name__ == "__main__":
    main()
