# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
"""Permissioned consensus security metadata.

The v2.6 sync layer limits voting to an enrolled validator set, requires
validator-key signatures, scopes proposals to epochs, and computes quorum over
the full configured set. A sufficiently large authorized coalition can still
approve malicious future proposals, so this is not a Byzantine-majority
resistance claim.
"""

import json
import os


CONSENSUS_MODEL_PERMISSIONED_QUORUM = "permissioned_quorum"
MAJORITY_ATTACK_NOTE = (
    "Permissioned membership blocks outsider/Sybil voting, but a sufficiently "
    "large authorized validator coalition can still approve malicious future proposals."
)


def _configured_validator_count() -> int:
    raw_ids = os.getenv("SMARTCAR_SYNC_VALIDATOR_IDS", "")
    ids = {item.strip() for item in raw_ids.split(",") if item.strip()}
    if ids:
        return len(ids)
    try:
        registry = json.loads(os.getenv("SMARTCAR_POA_AUTHORITY_REGISTRY_JSON", "{}") or "{}")
        if isinstance(registry, dict):
            return len([key for key in registry if str(key).strip()])
    except Exception:
        pass
    return 0


def consensus_security_metadata() -> dict:
    validator_count = _configured_validator_count()
    return {
        "consensus_model": CONSENSUS_MODEL_PERMISSIONED_QUORUM,
        "enforcement_layer": "python_sync_network",
        "configured": validator_count > 0,
        "validator_count": validator_count,
        "validator_membership_enforced": True,
        "vote_identity_bound_to_authenticated_session": True,
        "vote_signature_required": True,
        "duplicate_vote_rejected": True,
        "epoch_scoped": True,
        "proposal_hash_bound": True,
        "proposal_expiry_enforced": True,
        "quorum_basis": "configured_validator_set",
        "quorum_fraction": "2/3 default; configurable",
        "majority_attack_resistant": False,
        "protects_against_forward_majority_control": False,
        "dual_hash_chaining": True,
        "hash_collision_resistance": True,
        "retroactive_tamper_evidence": True,
        "notes": MAJORITY_ATTACK_NOTE,
        "secret_values_exposed": False,
    }
