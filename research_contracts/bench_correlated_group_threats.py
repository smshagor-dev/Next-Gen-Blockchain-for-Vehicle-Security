"""Paired synthetic threat-model stress test; NOT empirical V2X effectiveness.

Same incident observations are evaluated by four policies. Correlated honest
sensor errors and group-level compromises are generated independently of policy.
No actuation, network access, external dataset, or claimed statistical significance.
"""
import argparse
import csv
import math
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from v2x_evidence_gate import Observation, admit_hazard
from research_contracts.robust_group_policy import Report, evaluate


POLICIES = ("authentication_only", "sender_quorum", "strict_groups", "dissent_tolerant_groups")


def run(seed, trials, *, compromised_groups=1, honest_error=0.05, correlated_error=0.05):
    if (type(seed) is not int or type(trials) is not int or trials < 1
            or type(compromised_groups) is not int or not 0 <= compromised_groups <= 3
            or type(honest_error) not in (int, float) or not math.isfinite(honest_error)
            or type(correlated_error) not in (int, float) or not math.isfinite(correlated_error)
            or not 0 <= honest_error <= 1 or not 0 <= correlated_error <= 1):
        raise ValueError("invalid experiment parameters")
    rng = random.Random(seed)
    records = []
    # Two witnesses in A, one each in B and C. Same-group agreement is not independence.
    # Randomize the authentication-only primary to avoid a fixed A-group advantage.
    groups = ("A", "A", "B", "C")
    for incident in range(trials):
        truth = bool(rng.getrandbits(1))
        compromised = set(rng.sample(("A", "B", "C"), compromised_groups))
        common_flip = rng.random() < correlated_error
        group_flip = {g: rng.random() < honest_error for g in ("A", "B", "C")}
        values = tuple((not truth if g in compromised else
                        (truth != (common_flip or group_flip[g]))) for g in groups)
        obs = tuple(Observation(f"device-{i}", g, f"event-{incident}", 100., value, True)
                    for i, (g, value) in enumerate(zip(groups, values)))
        reports = tuple(Report(o.sender, o.trust_group, o.incident, o.observed_at,
                               o.hazard, o.authenticated) for o in obs)
        primary_index = rng.randrange(len(obs))
        verdicts = {
            "authentication_only": obs[primary_index].hazard,
            "sender_quorum": sum(o.hazard for o in obs) >= 2,
            "strict_groups": admit_hazard(obs[0], obs[1:], now=101.).admitted,
            "dissent_tolerant_groups": evaluate(reports, incident=obs[0].incident,
                                                now=101.).admitted,
        }
        for policy in POLICIES:
            accepted = verdicts[policy]
            records.append(dict(seed=seed, incident=incident, truth_hazard=int(truth),
                                compromised_groups=compromised_groups,
                                honest_error=honest_error, correlated_error=correlated_error,
                                group_compromise=";".join(sorted(compromised)),
                                observed_bits="".join(str(int(v)) for v in values),
                                auth_primary_sender=obs[primary_index].sender,
                                policy=policy, admitted=int(accepted),
                                false_admission=int(accepted and not truth),
                                missed_hazard=int(not accepted and truth)))
    assert len(records) == trials * len(POLICIES)
    return records


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=17)
    p.add_argument("--trials", type=int, default=1000)
    p.add_argument("--compromised-groups", type=int, default=1)
    p.add_argument("--honest-error", type=float, default=.05)
    p.add_argument("--correlated-error", type=float, default=.05)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    rows = run(a.seed, a.trials, compromised_groups=a.compromised_groups,
               honest_error=a.honest_error, correlated_error=a.correlated_error)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    for policy in POLICIES:
        subset = [r for r in rows if r["policy"] == policy]
        print(policy, "false_admissions", sum(r["false_admission"] for r in subset),
              "missed_hazards", sum(r["missed_hazard"] for r in subset))


if __name__ == "__main__":
    main()
