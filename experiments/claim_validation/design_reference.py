"""Design-based reference checks and observer trust-boundary sensitivity.

The reference implementation does not import the proposed claim gate or
runtime evidence collector. It uses the frozen experimental interventions
and independently recomputes the finite expected outcomes. It is not a
trusted external measurement or a blind human adjudication.
"""
from __future__ import annotations


REGISTRY_CELLS = {"registry_strict", "registry_with_compatibility", "registry_declared_open"}
GLOBAL_CELLS = {"global_lab", "global_declared_deny"}
EXPECTED_MODE = {
    "native_mlkem": "PQC_KEM",
    "forced_classical_ecdh": "ECDH",
    "forced_classical_psk": "PSK",
    "provider_missing_ecdh": "ECDH",
    "provider_missing_psk": "PSK",
    "malformed_kem_psk": "PSK",
}


def adjudicate(domain, row):
    """Return design truth, direct execution check, and independent design cell."""
    if domain == "consensus":
        n = row["controlled_voters"]
        valid = row["policy_allows_proposal"]
        if type(n) is not int or n not in range(4) or type(valid) is not bool:
            raise ValueError("invalid consensus intervention")
        ids = ("lab-v1", "lab-v2", "lab-v3")
        order = row["arrival_order"]
        if sorted(order) != list(ids):
            raise ValueError("invalid arrival order")
        controlled = set(ids[:n])
        yes = no = 0
        status = "PENDING"
        expected = []
        for voter in order:
            vote = valid or voter in controlled
            yes += int(vote)
            no += int(not vote)
            status = "ACCEPTED" if yes >= 2 else "REJECTED" if no >= 2 else "PENDING"
            expected.append({"voter": voter, "vote": vote, "status": status,
                             "yes": yes, "no": no})
            if status != "PENDING":
                break
        direct_agrees = (row["transitions"] == expected and row["final_status"] == status
                         and row["quorum_threshold"] == 2)
        return {"truth": status == "ACCEPTED", "direct_agrees": direct_agrees,
                "cell": f"controlled={n};policy={int(valid)}"}
    if domain == "identity":
        config, challenge = row["config"], row["challenge"]
        if config not in REGISTRY_CELLS | GLOBAL_CELLS | {"unconfigured_deny"}:
            raise ValueError("unknown identity configuration")
        if challenge not in {"enrolled_valid", "enrolled_wrong", "unlisted_shared", "unlisted_wrong"}:
            raise ValueError("unknown identity challenge")
        enrolled = config in REGISTRY_CELLS and challenge == "enrolled_valid"
        unlisted = config in GLOBAL_CELLS and challenge == "unlisted_shared"
        ack = enrolled or unlisted
        direct_agrees = (row["authenticated_ack"] is ack and row["bound_identity"] is ack
                         and row["unlisted_identity_accepted"] is unlisted)
        return {"truth": enrolled, "direct_agrees": direct_agrees,
                "cell": f"{config};{challenge}"}
    if domain == "pqc":
        config = row["config"]
        mode = EXPECTED_MODE[config]
        kem = "ML-KEM-512" if mode == "PQC_KEM" else ""
        direct_agrees = (row["matched_session"] is True and row["client_mode"] == mode
                         and row["server_mode"] == mode and row["negotiated_kem"] == kem)
        return {"truth": mode == "PQC_KEM", "direct_agrees": direct_agrees, "cell": config}
    raise ValueError("unknown domain")
