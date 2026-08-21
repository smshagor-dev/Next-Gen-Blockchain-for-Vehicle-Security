# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Lightweight DID for SmartCar using Lamport one-time signatures (hash-based).

Important security boundary:
Lamport is a ONE-TIME signature construction. A private key MUST NOT sign more
than one challenge. This module enforces one-time use in the identity object and
destroys its retained private-key references immediately after signing.

The DID proves control of signing material for the published DID document. It
does not make identity creation costly and does not provide Sybil resistance.
"""

import hashlib
import json
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Tuple


LAMPORT_KEY_TYPE = "LAMPORT-SHA3-256"
LAMPORT_BITS = 256
LAMPORT_SECRET_BYTES = 32


def sha3_256(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()


def _sha3_hex_bytes(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _canonical_json(data: Dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _msg_bits(message: str, bit_count: int = LAMPORT_BITS) -> List[int]:
    digest = hashlib.sha3_256(message.encode()).digest()
    bits: List[int] = []
    for byte in digest:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits[:bit_count]


def _new_lamport_keypair() -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    private_key: List[Tuple[str, str]] = []
    public_key: List[Tuple[str, str]] = []
    for _ in range(LAMPORT_BITS):
        secret_zero = secrets.token_bytes(LAMPORT_SECRET_BYTES)
        secret_one = secrets.token_bytes(LAMPORT_SECRET_BYTES)
        private_key.append((secret_zero.hex(), secret_one.hex()))
        public_key.append(
            (_sha3_hex_bytes(secret_zero), _sha3_hex_bytes(secret_one))
        )
    return private_key, public_key


@dataclass
class DIDIdentity:
    did: str
    controller: str
    public_key: List[Tuple[str, str]]
    private_key: List[Tuple[str, str]]
    created_at: str
    key_type: str = LAMPORT_KEY_TYPE
    used: bool = False
    _sign_lock: threading.Lock = field(
        default_factory=threading.Lock,
        repr=False,
        compare=False,
    )

    @classmethod
    def generate(cls, vehicle_id: str) -> "DIDIdentity":
        vehicle_id = str(vehicle_id).strip()
        if not vehicle_id:
            raise ValueError("vehicle_id is required")

        private_key, public_key = _new_lamport_keypair()
        did_seed = _canonical_json(
            {
                "vehicle_id": vehicle_id,
                "key_type": LAMPORT_KEY_TYPE,
                "public_key": public_key,
            }
        )
        did = "did:smartcar:" + sha3_256(did_seed)
        return cls(
            did=did,
            controller=vehicle_id,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    @property
    def exhausted(self) -> bool:
        return self.used or len(self.private_key) != LAMPORT_BITS

    @property
    def verification_method_id(self) -> str:
        return f"{self.did}#lamport-key-1"

    def sign_challenge(self, challenge: str) -> Dict:
        """Sign exactly one challenge and irreversibly exhaust this Lamport key."""
        challenge = str(challenge)
        if not challenge:
            raise ValueError("challenge is required")

        with self._sign_lock:
            if self.exhausted:
                raise RuntimeError(
                    "Lamport one-time key is exhausted; generate/rotate to a new DID key before signing again"
                )

            bits = _msg_bits(challenge)
            signature = [
                self.private_key[index][bit]
                for index, bit in enumerate(bits)
            ]

            # Lamport OTS private material must never be reused. Clear retained
            # references before returning the proof so every subsequent call
            # fails closed even if the `used` flag is accidentally modified.
            self.used = True
            self.private_key.clear()

        return {
            "did": self.did,
            "verification_method": self.verification_method_id,
            "key_type": self.key_type,
            "one_time_key": True,
            "challenge_hash": sha3_256(challenge),
            "signature": signature,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def successor(self) -> "DIDIdentity":
        """Generate a fresh successor identity after this one-time key is used.

        A successor has a new DID because the DID is cryptographically bound to
        its public key. Applications must publish/use the returned DID document.
        """
        return DIDIdentity.generate(vehicle_id=self.controller)

    def to_document(self) -> Dict:
        return {
            "id": self.did,
            "controller": self.controller,
            "created_at": self.created_at,
            "verificationMethod": [
                {
                    "id": self.verification_method_id,
                    "type": self.key_type,
                    "controller": self.controller,
                    "oneTimeUse": True,
                    "publicKeyHashPairs": self.public_key,
                }
            ],
            "authentication": [self.verification_method_id],
        }


def verify_did_proof(challenge: str, proof: Dict, did_document: Dict) -> bool:
    """Verify one Lamport proof against a DID document, failing closed."""
    try:
        if not isinstance(proof, dict) or not isinstance(did_document, dict):
            return False
        if proof.get("did") != did_document.get("id"):
            return False
        if proof.get("challenge_hash") != sha3_256(str(challenge)):
            return False
        if proof.get("one_time_key") is not True:
            return False

        methods = did_document.get("verificationMethod", [])
        if not isinstance(methods, list) or len(methods) != 1:
            return False
        key_info = methods[0]
        if not isinstance(key_info, dict):
            return False

        method_id = str(key_info.get("id", ""))
        if proof.get("verification_method") != method_id:
            return False
        if proof.get("key_type") != key_info.get("type"):
            return False
        if key_info.get("oneTimeUse") is not True:
            return False

        public_pairs = key_info.get("publicKeyHashPairs", [])
        signature = proof.get("signature", [])
        if (
            not isinstance(public_pairs, list)
            or not isinstance(signature, list)
            or len(public_pairs) != LAMPORT_BITS
            or len(signature) != LAMPORT_BITS
        ):
            return False

        bits = _msg_bits(str(challenge))
        for index, bit in enumerate(bits):
            pair = public_pairs[index]
            sig_part = signature[index]
            if (
                not isinstance(pair, (list, tuple))
                or len(pair) != 2
                or not isinstance(sig_part, str)
            ):
                return False

            raw_secret = bytes.fromhex(sig_part)
            if len(raw_secret) != LAMPORT_SECRET_BYTES:
                return False
            expected_hash = str(pair[bit])
            if not secrets.compare_digest(
                _sha3_hex_bytes(raw_secret),
                expected_hash,
            ):
                return False
        return True
    except (TypeError, ValueError, IndexError):
        return False
