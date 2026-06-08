# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
"""Consensus threat-model metadata.

Dual SHA2/SHA3 chaining is an audit-integrity mechanism. It does not stop a
validator majority from approving malicious but syntactically valid future
blocks.
"""


CONSENSUS_MODEL_SIMPLE_MAJORITY = "simple_majority"

MAJORITY_ATTACK_NOTE = (
    "A voting majority can approve syntactically valid malicious blocks without "
    "finding hash collisions."
)


def consensus_security_metadata() -> dict:
    return {
        "consensus_model": CONSENSUS_MODEL_SIMPLE_MAJORITY,
        "majority_attack_resistant": False,
        "dual_hash_chaining": True,
        "hash_collision_resistance": True,
        "retroactive_tamper_evidence": True,
        "protects_against_forward_majority_control": False,
        "notes": MAJORITY_ATTACK_NOTE,
    }
