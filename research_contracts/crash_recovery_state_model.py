"""Non-actuating exhaustive crash/recovery state model for replay reservations.

This model is NOT an implementation of a trusted anchor, a vehicle controller,
or a substitute for crash experiments against production persistence.
"""
from dataclasses import dataclass
from itertools import product
import json
import argparse

@dataclass(frozen=True)
class State:
    local: bool = False
    anchor: bool = False
    authorized: bool = False

def step(state: State, action: str) -> State:
    if action == "reserve_anchor":
        return State(state.local, True, state.authorized)
    if action == "commit_local":
        return State(True, state.anchor, state.authorized)
    if action == "authorize":
        # Authorization is safety-isolated: both durable claims required.
        if not (state.local and state.anchor):
            return state
        return State(True, True, True)
    if action in ("crash", "restart", "retry"):
        # A retry does not repair a partially committed transaction.
        return state
    raise ValueError(action)

def explore(depth: int = 5):
    if depth < 0 or depth > 10:
        raise ValueError("depth must be between 0 and 10")
    actions = ("reserve_anchor", "commit_local", "authorize", "crash", "restart", "retry")
    reachable = {State()}
    transitions = 0
    for _ in range(depth):
        new = set(reachable)
        for state in reachable:
            for action in actions:
                successor = step(state, action)
                transitions += 1
                assert not successor.authorized or (successor.local and successor.anchor), (
                    "unsafe authorization", state, action, successor
                )
                assert not state.authorized or successor.authorized, "authorization lost"
                new.add(successor)
        reachable = new
    partial = sum(s.local != s.anchor for s in reachable)
    return {"depth": depth, "reachable_states": len(reachable),
            "transitions_checked": transitions, "partial_states": partial,
            "unsafe_states": 0,
            "limitations": "abstract monotonic claims; excludes rollback, Byzantine anchor, races, actuator timing"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--depth", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(explore(args.depth), sort_keys=True))

if __name__ == "__main__":
    main()
