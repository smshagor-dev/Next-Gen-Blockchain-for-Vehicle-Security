# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Lightweight DID for SmartCar using Lamport one-time signatures (hash-based).
No central server is required for verification:
verifier only needs DID document + challenge + proof.

Security boundary: Lamport DID provides cryptographic identity authenticity.
It proves control of signing secrets for a DID document, but it does not make
identity creation costly and does not provide Sybil resistance by itself.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Tuple


def sha3_256(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()


def _sha3_hex_bytes(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _canonical_json(data: Dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _msg_bits(message: str, bit_count: int = 256) -> List[int]:
    digest = hashlib.sha3_256(message.encode()).digest()
    bits: List[int] = []
    for b in digest:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits[:bit_count]


@dataclass
class DIDIdentity:
    did: str
    controller: str
    public_key: List[Tuple[str, str]]
    private_key: List[Tuple[str, str]]
    created_at: str
    key_type: str = "LAMPORT-SHA3-256"

    @classmethod
    def generate(cls, vehicle_id: str) -> "DIDIdentity":
        priv: List[Tuple[str, str]] = []
        pub: List[Tuple[str, str]] = []
        for _ in range(256):
            s0 = secrets.token_bytes(32)
            s1 = secrets.token_bytes(32)
            priv.append((s0.hex(), s1.hex()))
            pub.append((_sha3_hex_bytes(s0), _sha3_hex_bytes(s1)))

        did_seed = _canonical_json({
            "vehicle_id": vehicle_id,
            "key_type": "LAMPORT-SHA3-256",
            "public_key": pub
        })
        did = "did:smartcar:" + sha3_256(did_seed)
        return cls(
            did=did,
            controller=vehicle_id,
            public_key=pub,
            private_key=priv,
            created_at=datetime.now(timezone.utc).isoformat()
        )

    def sign_challenge(self, challenge: str) -> Dict:
        bits = _msg_bits(challenge)
        sig_parts: List[str] = []
        for i, bit in enumerate(bits):
            sig_parts.append(self.private_key[i][bit])
        return {
            "did": self.did,
            "key_type": self.key_type,
            "challenge_hash": sha3_256(challenge),
            "signature": sig_parts,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

    def to_document(self) -> Dict:
        return {
            "id": self.did,
            "controller": self.controller,
            "created_at": self.created_at,
            "verificationMethod": [{
                "id": f"{self.did}#lamport-key-1",
                "type": self.key_type,
                "controller": self.controller,
                "publicKeyHashPairs": self.public_key
            }],
            "authentication": [f"{self.did}#lamport-key-1"]
        }


def verify_did_proof(challenge: str, proof: Dict, did_document: Dict) -> bool:
    if not proof or not did_document:
        return False
    if proof.get("did") != did_document.get("id"):
        return False
    methods = did_document.get("verificationMethod", [])
    if not methods:
        return False
    key_info = methods[0]
    public_pairs = key_info.get("publicKeyHashPairs", [])
    signature = proof.get("signature", [])
    if len(public_pairs) != 256 or len(signature) != 256:
        return False
    if proof.get("challenge_hash") != sha3_256(challenge):
        return False

    bits = _msg_bits(challenge)
    for i, bit in enumerate(bits):
        expected_hash = public_pairs[i][bit]
        if _sha3_hex_bytes(bytes.fromhex(signature[i])) != expected_hash:
            return False
    return True

