# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
"""Shared security capability metadata.

This is deliberately conservative: the prototype is hybrid security, not
end-to-end post-quantum security.
"""

PQ_HYBRID_AUTHENTICATION = "PQ_HYBRID_AUTHENTICATION"
CLASSICAL_PRIVACY_COMMITMENT = "CLASSICAL_PRIVACY_COMMITMENT"
LEGACY_ECDH_FALLBACK_DISABLED_BY_DEFAULT = "LEGACY_ECDH_FALLBACK_DISABLED_BY_DEFAULT"

HYBRID_SECURITY_SUMMARY = (
    "Hybrid security: post-quantum key establishment with classical "
    "commitment/proof components."
)

ECDH_P256_WARNING = "WARNING: ECDH-P256 fallback is classical and not post-quantum secure."

ADVERSARIAL_VALIDATION_METADATA = {
    "adversarial_validation_level": "single_run_sanity_check",
    "supports_general_detection_claim": False,
    "detection_rate_headline_allowed": False,
    "attack_trials_per_type": 1,
    "statistical_significance": False,
    "known_trivial_triggers": ["350_kmh_speed", "100x_fl_weight_delta"],
}

CONTRIBUTION_BOUNDARY_METADATA = {
    "claims_new_cryptographic_primitive": False,
    "contribution_type": "system_integration_and_validation_transparency",
    "reused_components": [
        "ML-KEM/Kyber",
        "Pedersen commitments",
        "Lamport OTS/DID",
        "SHA2/SHA3 hashing",
        "mTLS/API security",
        "majority blockchain logic",
        "robust aggregation concepts",
    ],
    "novel_components": [
        "cross-layer prototype integration",
        "security capability reporting",
        "assumption-aware dashboard/API metadata",
        "validation-plan scaffolding",
    ],
}

COMPLEXITY_BOUNDARY_METADATA = {
    "overall_complexity_claim": "component_dependent",
    "full_system_o_n_claim": False,
    "naive_full_mesh_network_volume": "O(n^2)",
    "single_proposal_vote_collection": "O(n)",
    "fl_aggregation": "O(n*d)",
    "chain_audit": "O(k)",
}

REVIEWER_AUDIT_METADATA = {
    "paper_ready_claim_status": "corrected_but_requires_new_experiments",
    "full_post_quantum_security_claim": False,
    "sybil_resistance_claim": False,
    "majority_attack_resistance_claim": False,
    "byzantine_robustness_claim": False,
    "general_100_percent_detection_claim": False,
    "new_crypto_primitive_claim": False,
    "whole_system_o_n_claim": False,
    "secure_aggregation_claim": False,
    "canonical_layer_count": "six implemented prototype layers",
    "canonical_latency": "5.34 ms warm-start prototype pipeline latency",
}


def security_capability_output(ecdh_enabled: bool = False) -> dict:
    fallback_state = "enabled/classical" if ecdh_enabled else "disabled_by_default/classical"
    return {
        "security_modes": [
            PQ_HYBRID_AUTHENTICATION,
            CLASSICAL_PRIVACY_COMMITMENT,
            LEGACY_ECDH_FALLBACK_DISABLED_BY_DEFAULT,
        ],
        "summary": HYBRID_SECURITY_SUMMARY,
        "key_establishment": "ML-KEM/Kyber - post-quantum",
        "commitment_hiding": "Pedersen - information-theoretic hiding",
        "commitment_binding": "Pedersen - classical discrete-log assumption",
        "range_proof_soundness": "Schnorr/classical assumption",
        "fallback_ecdh_p256": fallback_state,
    }


def adversarial_validation_metadata() -> dict:
    return dict(ADVERSARIAL_VALIDATION_METADATA)


def contribution_boundary_metadata() -> dict:
    return {
        "claims_new_cryptographic_primitive": CONTRIBUTION_BOUNDARY_METADATA[
            "claims_new_cryptographic_primitive"
        ],
        "contribution_type": CONTRIBUTION_BOUNDARY_METADATA["contribution_type"],
        "reused_components": list(CONTRIBUTION_BOUNDARY_METADATA["reused_components"]),
        "novel_components": list(CONTRIBUTION_BOUNDARY_METADATA["novel_components"]),
    }


def complexity_boundary_metadata() -> dict:
    return dict(COMPLEXITY_BOUNDARY_METADATA)


def reviewer_audit_metadata() -> dict:
    return dict(REVIEWER_AUDIT_METADATA)
