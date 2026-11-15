"""Executable finite-state safety model for remote V2X command authorization.

This is an OFFLINE reference policy. It NEVER actuates a vehicle. In
particular a remotely relayed hazard does not grant braking, steering or
throttle authority. A local emergency latch dominates all remote requests.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from itertools import product
from typing import Literal

RemoteAction = Literal["network_alert", "remote_brake", "remote_steer", "remote_throttle"]
ACTIONS = ("network_alert", "remote_brake", "remote_steer", "remote_throttle")

@dataclass(frozen=True)
class State:
    local_emergency: bool = False
    local_reset_authorized: bool = False
    transport_authenticated: bool = False
    fresh_nonce: bool = False
    evidence_admitted: bool = False
    network_available: bool = True

@dataclass(frozen=True)
class Outcome:
    state: State
    network_relay: bool
    vehicle_actuation: bool
    reason: str

def decide(state: State, action: RemoteAction) -> Outcome:
    if type(state) is not State or action not in ACTIONS:
        raise ValueError("unsupported state or remote action")
    if any(type(getattr(state, field)) is not bool for field in State.__dataclass_fields__):
        raise ValueError("state must use strict booleans")
    if action != "network_alert":
        return Outcome(state, False, False, "REMOTE_ACTUATION_FORBIDDEN")
    if state.local_emergency:
        return Outcome(state, False, False, "LOCAL_EMERGENCY_LATCHED")
    if not state.network_available:
        return Outcome(state, False, False, "NETWORK_UNAVAILABLE")
    if not state.transport_authenticated or not state.fresh_nonce:
        return Outcome(state, False, False, "UNAUTHENTICATED_OR_REPLAYED")
    if not state.evidence_admitted:
        return Outcome(state, False, False, "INSUFFICIENT_EVIDENCE")
    return Outcome(state, True, False, "NETWORK_ALERT_RELAYED")

def transition(state: State, event: str) -> State:
    """Local safety latch can only clear via a separately authorized local reset."""
    if type(state) is not State:
        raise ValueError("invalid state")
    if event == "local_emergency":
        return replace(state, local_emergency=True, local_reset_authorized=False)
    if event == "local_reset":
        if state.local_reset_authorized:
            return replace(state, local_emergency=False, local_reset_authorized=False)
        return state
    if event == "authorize_local_reset":
        return replace(state, local_reset_authorized=True)
    if event == "network_down":
        return replace(state, network_available=False)
    if event == "network_up":
        return replace(state, network_available=True)
    if event == "invalidate_session":
        return replace(state, transport_authenticated=False, fresh_nonce=False)
    if event == "replay_detected":
        return replace(state, fresh_nonce=False)
    raise ValueError("unsupported transition")

def check_all_states() -> dict:
    """Exhaustively enumerate 2^6 Boolean states and four remote requests."""
    checked = 0
    relayed = 0
    for bits in product((False, True), repeat=6):
        state = State(*bits)
        for action in ACTIONS:
            result = decide(state, action)
            checked += 1
            assert result.state == state
            assert result.vehicle_actuation is False
            if action != "network_alert":
                assert result.network_relay is False
            if state.local_emergency or not state.network_available:
                assert result.network_relay is False
            if not state.transport_authenticated or not state.fresh_nonce:
                assert result.network_relay is False
            if not state.evidence_admitted:
                assert result.network_relay is False
            if result.network_relay:
                assert action == "network_alert"
                relayed += 1
        for event in ("network_down", "network_up", "invalidate_session",
                      "replay_detected", "local_reset"):
            next_state = transition(state, event)
            if state.local_emergency and not (
                event == "local_reset" and state.local_reset_authorized
            ):
                assert next_state.local_emergency
    return {"states": 64, "remote_requests": checked,
            "network_relays": relayed, "actuation_requests_accepted": 0,
            "publication_ready": False,
            "scope": "bounded software reference model, not deployed vehicle control"}

if __name__ == "__main__":
    import json
    print(json.dumps(check_all_states(), sort_keys=True))
