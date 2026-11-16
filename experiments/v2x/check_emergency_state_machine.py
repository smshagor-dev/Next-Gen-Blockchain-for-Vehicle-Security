"""Bounded abstract V2X emergency state-machine exploration; not production proof."""
from collections import deque
from dataclasses import dataclass
import argparse
import json

REMOTE = ("alert", "brake", "steer", "throttle", "reset_emergency")
EVENTS = ("local_emergency", "local_reset", "restart", "sensor_fault", "sensor_recover") + tuple("remote_" + x for x in REMOTE)

@dataclass(frozen=True)
class State:
    emergency: bool = False
    sensor_healthy: bool = True

def transition(state, event, *, authenticated=False, fresh=False, evidence=False):
    if event not in EVENTS:
        raise ValueError("unknown event")
    if any(type(g) is not bool for g in (authenticated, fresh, evidence)):
        raise ValueError("gates must be boolean")
    if event == "local_emergency":
        return State(True, state.sensor_healthy), "local_stop"
    if event == "local_reset":
        return (State(False, True), "local_reset_accepted") if state.sensor_healthy else (state, "local_reset_blocked_fault")
    if event == "restart":
        return state, "restarted_no_actuation"
    if event == "sensor_fault":
        return State(state.emergency, False), "sensor_fault_isolated"
    if event == "sensor_recover":
        return State(state.emergency, True), "sensor_recovered"
    if state.emergency:
        return state, "blocked_local_emergency"
    if not state.sensor_healthy:
        return state, "blocked_sensor_fault"
    if event != "remote_alert":
        return state, "blocked_remote_actuation"
    if not authenticated:
        return state, "blocked_authentication"
    if not fresh:
        return state, "blocked_replay"
    if not evidence:
        return state, "blocked_evidence"
    return state, "network_alert_only"

def explore(depth=7):
    if type(depth) is not int or not 0 <= depth <= 12:
        raise ValueError("depth must be integer 0..12")
    initial = State()
    queue = deque([(initial, ())])
    visited = {(initial, 0)}
    edges = 0
    while queue:
        state, path = queue.popleft()
        if len(path) == depth:
            continue
        for event in EVENTS:
            gates = ((False, False, False), (True, True, True)) if event.startswith("remote_") else ((False, False, False),)
            for a, f, e in gates:
                nxt, action = transition(state, event, authenticated=a, fresh=f, evidence=e)
                edges += 1
                trace = path + ((event, a, f, e),)
                if event.startswith("remote_") and nxt.emergency != state.emergency:
                    raise AssertionError(("remote changed local emergency", trace))
                if event == "restart" and nxt.emergency != state.emergency:
                    raise AssertionError(("restart lost emergency", trace))
                if state.emergency and event.startswith("remote_") and action != "blocked_local_emergency":
                    raise AssertionError(("local emergency bypass", trace))
                if action == "network_alert_only" and (event != "remote_alert" or not (a and f and e) or state.emergency or not state.sensor_healthy):
                    raise AssertionError(("unauthorized alert", trace))
                node = (nxt, len(trace))
                if node not in visited:
                    visited.add(node)
                    queue.append((nxt, trace))
    return {"model": "abstract_reference_not_production_proof", "depth": depth,
            "reachable_state_depth_pairs": len(visited), "transitions_checked": edges,
            "violations": 0, "publication_ready": False,
            "assumptions": ["Emergency latch persists outside process memory",
                            "Local reset is trusted physical input",
                            "Sensor health is trustworthy",
                            "No asynchronous actuation or network side effects modeled"]}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--depth", type=int, default=7)
    print(json.dumps(explore(p.parse_args().depth), indent=2))
