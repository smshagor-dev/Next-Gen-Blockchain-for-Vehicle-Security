"""Non-actuating matched-trace adversarial controls for evidence quorum.

All outcomes are synthetic counterexamples, never empirical vehicle effectiveness.
"""
import argparse
import json
from research_contracts.evidence_gate_experiment import EvidenceGate, Observation


def run_case(case: str):
    if case not in {"honest", "collusion", "partition", "replay", "emergency_stop"}:
        raise ValueError("unknown case")
    gate = EvidenceGate(quorum=2)
    incident, epoch, event = "trial-0", 1, "hazard"
    def observation(sender, nonce, corroborates=True):
        return Observation(incident, sender, epoch, nonce, event, True, corroborates)
    # An enrolled malicious node can make an authenticated false claim.
    first = observation("enrolled-A", "nonce-a")
    second = observation("enrolled-B", "nonce-b")
    if case == "honest":
        truth, stream, stop = True, [first, second], False
    elif case == "collusion":
        truth, stream, stop = False, [first, second], False
    elif case == "partition":
        truth, stream, stop = True, [first], False
    elif case == "replay":
        truth, stream, stop = False, [first, first], False
    else:
        truth, stream, stop = True, [first, second], True
    baseline = any(o.authenticated and o.corroborates for o in stream) and not stop
    gate_decisions = [gate.admit(o, local_stop=stop) for o in stream]
    gated = any(gate_decisions)
    return {"case": case, "truth": truth, "authenticated_only": baseline,
            "evidence_gate": gated, "local_stop": stop,
            "observations": len(stream), "kind": "synthetic_counterexample_nonpublishable"}


def evaluate_all():
    return [run_case(c) for c in
            ("honest", "collusion", "partition", "replay", "emergency_stop")]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=["honest", "collusion", "partition",
                                          "replay", "emergency_stop", "all"], default="all")
    args = parser.parse_args()
    print(json.dumps(evaluate_all() if args.case == "all" else run_case(args.case),
                     sort_keys=True))
