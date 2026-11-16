"""Exhaustive abstract one-step safety model; NOT a proof of production hardware."""
from dataclasses import dataclass
from itertools import product
import json

COMMANDS = ("alert", "brake", "steer", "throttle", "reset_emergency")

@dataclass(frozen=True)
class State:
    emergency: bool
    local_clear_authorized: bool

def transition(state, *, command, authenticated, fresh, evidence, local_set, local_clear):
    if command not in COMMANDS:
        raise ValueError("unknown command")
    emergency = True if local_set else (False if local_clear and state.local_clear_authorized else state.emergency)
    next_state = State(emergency, state.local_clear_authorized)
    admitted = command == "alert" and authenticated and fresh and evidence and not emergency
    return next_state, ("network_alert" if admitted else "blocked")

def unsafe_baseline(state, *, command, authenticated, fresh, evidence, local_set, local_clear):
    # Deliberately unsafe reference: authenticated remote reset and physical actuation.
    emergency = True if local_set else (False if local_clear else state.emergency)
    if command == "reset_emergency" and authenticated:
        emergency = False
    next_state = State(emergency, state.local_clear_authorized)
    admitted = authenticated and fresh and evidence and not emergency
    return next_state, ("remote_actuation" if admitted and command != "alert" else "network_alert" if admitted else "blocked")

def explore(policy=transition):
    checked, failures, witness = 0, 0, None
    for emergency, local_clear_authorized, command, authenticated, fresh, evidence, local_set, local_clear in product(
        (False, True), (False, True), COMMANDS, (False, True), (False, True), (False, True), (False, True), (False, True)
    ):
        before = State(emergency, local_clear_authorized)
        after, action = policy(before, command=command, authenticated=authenticated,
                               fresh=fresh, evidence=evidence, local_set=local_set, local_clear=local_clear)
        checked += 1
        violations = []
        if action == "remote_actuation":
            violations.append("no_remote_actuation")
        if before.emergency and not (local_clear and before.local_clear_authorized) and not local_set and not after.emergency:
            violations.append("emergency_cannot_be_remotely_cleared")
        if local_set and not after.emergency:
            violations.append("local_emergency_dominates")
        if action == "network_alert" and not (command == "alert" and authenticated and fresh and evidence and not after.emergency):
            violations.append("alert_requires_all_evidence_gates")
        if violations:
            failures += 1
            if witness is None:
                witness = {"state": before.__dict__, "inputs": dict(command=command, authenticated=authenticated,
                    fresh=fresh, evidence=evidence, local_set=local_set, local_clear=local_clear),
                    "after": after.__dict__, "action": action, "violations": violations}
    return {"states_and_inputs_checked": checked, "violating_cases": failures,
            "first_counterexample": witness,
            "scope": "abstract one-step exhaustive finite-state model, not hardware proof"}

def main():
    safe, baseline = explore(), explore(unsafe_baseline)
    assert safe["violating_cases"] == 0
    assert baseline["violating_cases"] > 0
    print(json.dumps({"safe_policy": safe, "unsafe_reference_baseline": baseline}, indent=2))

if __name__ == "__main__":
    main()
