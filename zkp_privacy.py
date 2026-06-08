# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Lightweight privacy-preserving proofs for telemetry sharing.

This module provides commitment-based proofs to verify:
1) Knowledge of committed sensitive values (without revealing values)
2) Speed policy compliance (value <= limit) using commitment relation

Note: This is a practical educational construction, not a full formal ZK range proof
like Bulletproofs. It is a CLASSICAL_SECURITY privacy/proof component:
Pedersen hiding is information-theoretic, but binding/soundness relies on
discrete-log assumptions and is not post-quantum secure.
"""

import hashlib
import secrets
from typing import Dict, Tuple

from env_config import load_project_env_once, get_env

load_project_env_once()

# RFC 3526, 2048-bit MODP Group (Group 14).
# CLASSICAL_SECURITY: MODP/DDH discrete-log assumptions are not post-quantum secure.
_RFC3526_GROUP14_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF"
)


def _parse_int_env(name: str, default: int) -> int:
    """Parse integer env values from decimal or hex."""
    raw = get_env(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw, 0)
    except Exception:
        return default


def _derive_h(p: int, g: int) -> int:
    """Derive secondary generator-like element deterministically."""
    h_seed = int(hashlib.sha3_256(f"{p}|{g}|smartcar_zkp_h".encode()).hexdigest(), 16)
    # Keep value in [2, p-2] and avoid colliding with g.
    h = 2 + (h_seed % max(2, p - 3))
    if h == g:
        h = 2 + ((h + 1) % max(2, p - 3))
    return h


def _load_group_params() -> Tuple[int, int, int, int]:
    """Load ZKP group params from standard set with optional env overrides."""
    param_set = get_env("SMARTCAR_ZKP_PARAM_SET", "RFC3526_GROUP14").strip().upper()

    if param_set == "MERSENNE_521":
        p = (1 << 521) - 1
        g = 5
        h = 7
    else:
        p = int(_RFC3526_GROUP14_P_HEX, 16)
        g = 2
        h = _derive_h(p, g)

    p = _parse_int_env("SMARTCAR_ZKP_P", p)
    g = _parse_int_env("SMARTCAR_ZKP_G", g)
    h = _parse_int_env("SMARTCAR_ZKP_H", h)

    # Fallback safety if invalid override is provided.
    if p <= 11:
        p = int(_RFC3526_GROUP14_P_HEX, 16)
    if g <= 1 or g >= p:
        g = 2
    if h <= 1 or h >= p or h == g:
        h = _derive_h(p, g)

    q = p - 1
    return p, q, g, h


P, Q, G, H = _load_group_params()

PEDERSEN_MODE_COMMIT_ONLY = "COMMIT_ONLY"
PEDERSEN_MODE_AGGREGATE_OPENING = "AGGREGATE_OPENING"
PEDERSEN_MODE_SECURE_AGGREGATION_FUTURE = "SECURE_AGGREGATION_FUTURE"

PEDERSEN_PRIVACY_METADATA = {
    "pedersen_mode": PEDERSEN_MODE_COMMIT_ONLY,
    "commitment_homomorphic": True,
    "aggregate_statistics_recoverable": False,
    "requires_opening_for_aggregate": True,
    "secure_aggregation_implemented": False,
}


def _h(data: str) -> int:
    """Hash arbitrary text into field order."""
    return int(hashlib.sha3_256(data.encode()).hexdigest(), 16) % Q


def pedersen_privacy_metadata() -> Dict:
    """Return the active Pedersen aggregation/privacy mode.

    Pedersen commitments support additive homomorphism over committed values,
    but the aggregate remains hidden unless participants provide valid openings
    or a separate secure aggregation / zero-knowledge disclosure protocol is
    implemented.
    """
    return dict(PEDERSEN_PRIVACY_METADATA)


def commit(value: int, blind: int = None) -> Tuple[int, int]:
    """Create Pedersen-like commitment for integer value.

    Pedersen hiding is information-theoretic, but binding/soundness relies on
    discrete-log assumptions and is not post-quantum secure.
    """
    r = blind if blind is not None else secrets.randbelow(Q - 1) + 1
    c = (pow(G, value % Q, P) * pow(H, r, P)) % P
    return c, r


def prove_knowledge(commitment: int, value: int, blind: int, context: str) -> Dict:
    """Create Schnorr-style knowledge proof for a commitment opening.

    CLASSICAL_SECURITY: Schnorr-style proof soundness relies on discrete log.
    """
    k1 = secrets.randbelow(Q - 1) + 1
    k2 = secrets.randbelow(Q - 1) + 1
    t = (pow(G, k1, P) * pow(H, k2, P)) % P
    ch = _h(f"{commitment}|{t}|{context}")
    s1 = (k1 + ch * (value % Q)) % Q
    s2 = (k2 + ch * (blind % Q)) % Q
    return {
        "t": str(t),
        "s1": str(s1),
        "s2": str(s2),
    }


def verify_knowledge(commitment: int, proof: Dict, context: str) -> bool:
    """Verify commitment opening knowledge proof."""
    try:
        t = int(proof["t"])
        s1 = int(proof["s1"])
        s2 = int(proof["s2"])
    except Exception:
        return False
    ch = _h(f"{commitment}|{t}|{context}")
    lhs = (pow(G, s1, P) * pow(H, s2, P)) % P
    rhs = (t * pow(commitment, ch, P)) % P
    return lhs == rhs


def create_speed_limit_proof(speed_kmh: float, speed_limit_kmh: int, context: str) -> Dict:
    """Build privacy-preserving proof that speed is within a limit."""
    speed = max(0, int(round(speed_kmh)))
    if speed > speed_limit_kmh:
        # Do not create a dishonest proof.
        return {
            "scheme": "COMMITMENT_KNOWLEDGE_LEQ",
            "valid": False,
            "reason": "SPEED_EXCEEDS_LIMIT",
            "limit": speed_limit_kmh,
        }

    diff = speed_limit_kmh - speed
    c_speed, r_speed = commit(speed)
    c_diff, r_diff = commit(diff)
    relation_blind = (r_speed + r_diff) % Q

    proof_speed = prove_knowledge(c_speed, speed, r_speed, context + "|speed")
    proof_diff = prove_knowledge(c_diff, diff, r_diff, context + "|diff")

    return {
        "scheme": "COMMITMENT_KNOWLEDGE_LEQ",
        "valid": True,
        "limit": speed_limit_kmh,
        "commit_speed": str(c_speed),
        "commit_diff": str(c_diff),
        "proof_speed": proof_speed,
        "proof_diff": proof_diff,
        "relation_blind": str(relation_blind),
    }


def verify_speed_limit_proof(proof: Dict, context: str) -> bool:
    """Verify speed-limit compliance proof without revealing speed."""
    if not proof or proof.get("scheme") != "COMMITMENT_KNOWLEDGE_LEQ":
        return False
    if not proof.get("valid", False):
        return False
    try:
        limit = int(proof["limit"])
        c_speed = int(proof["commit_speed"])
        c_diff = int(proof["commit_diff"])
        relation_blind = int(proof["relation_blind"])
    except Exception:
        return False

    if not verify_knowledge(c_speed, proof.get("proof_speed", {}), context + "|speed"):
        return False
    if not verify_knowledge(c_diff, proof.get("proof_diff", {}), context + "|diff"):
        return False

    lhs = (c_speed * c_diff) % P
    rhs = (pow(G, limit % Q, P) * pow(H, relation_blind % Q, P)) % P
    return lhs == rhs


def create_location_ownership_proof(lat: float, lon: float, context: str) -> Dict:
    """Create proof that sender knows committed location token."""
    loc_str = f"{lat:.6f},{lon:.6f}"
    loc_secret = _h("LOC|" + loc_str)
    c_loc, r_loc = commit(loc_secret)
    proof_loc = prove_knowledge(c_loc, loc_secret, r_loc, context + "|location")
    return {
        "scheme": "COMMITMENT_KNOWLEDGE",
        "commit_location": str(c_loc),
        "proof_location": proof_loc,
    }


def verify_location_ownership_proof(proof: Dict, context: str) -> bool:
    """Verify location ownership commitment proof."""
    if not proof or proof.get("scheme") != "COMMITMENT_KNOWLEDGE":
        return False
    try:
        c_loc = int(proof["commit_location"])
    except Exception:
        return False
    return verify_knowledge(c_loc, proof.get("proof_location", {}), context + "|location")

