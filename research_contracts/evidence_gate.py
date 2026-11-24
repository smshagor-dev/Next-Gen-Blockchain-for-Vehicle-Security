"""Simulation-only evidence-gated V2X admission; NEVER authorizes physical actuation.

Distinct trust dimensions: enrolled identity, independent corroboration,
measurement plausibility, and locally controlled emergency precedence.
An attacker with a valid enrolled key can still supply false measurements.
"""
from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet

class Decision(str, Enum):
    REJECT = 'reject'
    QUARANTINE = 'quarantine'
    ADMIT_EVIDENCE = 'admit_evidence'

@dataclass(frozen=True)
class Observation:
    authenticated: bool
    fresh: bool
    nonce_unique: bool
    plausible: bool
    corroborating_devices: FrozenSet[str]
    reporting_device: str
    independent_sources_required: int = 2
    local_emergency_active: bool = False

@dataclass(frozen=True)
class Result:
    decision: Decision
    reason: str
    physical_command_authorized: bool = False

def decide(observation: Observation) -> Result:
    """Pure fail-closed admission; remote evidence never overrides local stop."""
    if type(observation) is not Observation:
        raise TypeError('Observation required')
    if observation.local_emergency_active:
        return Result(Decision.REJECT, 'LOCAL_EMERGENCY_PRECEDENCE')
    if not (observation.authenticated and observation.fresh and observation.nonce_unique):
        return Result(Decision.REJECT, 'IDENTITY_FRESHNESS_OR_REPLAY')
    if not observation.plausible:
        return Result(Decision.QUARANTINE, 'IMPLAUSIBLE_SIGNED_MEASUREMENT')
    if type(observation.independent_sources_required) is not int or not 1 <= observation.independent_sources_required <= 32:
        return Result(Decision.REJECT, 'INVALID_QUORUM_POLICY')
    if not observation.reporting_device or any(not isinstance(x, str) or not x for x in observation.corroborating_devices):
        return Result(Decision.REJECT, 'INVALID_SOURCE_IDENTITY')
    independent = observation.corroborating_devices - {observation.reporting_device}
    if len(independent) < observation.independent_sources_required:
        return Result(Decision.QUARANTINE, 'INSUFFICIENT_INDEPENDENT_EVIDENCE')
    return Result(Decision.ADMIT_EVIDENCE, 'CORROBORATED_NONACTUATING_EVENT')
