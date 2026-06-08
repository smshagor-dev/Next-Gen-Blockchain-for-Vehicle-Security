# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
SmartCar Blockchain Python Core
SHA2 + SHA3 Dual Hash Implementation
Encryption, Key Management, Sync Protocol
"""

import hashlib
import json
import time
import os
import shutil
import struct
import base64
import secrets
import hmac
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from pathlib import Path
import threading
import logging
import uuid

try:
    from env_config import load_project_env_once, get_env, get_int, get_bool
except Exception:
    from env_config import load_project_env_once, get_env, get_int, get_bool

try:
    from did_identity import DIDIdentity, verify_did_proof
except Exception:
    from did_identity import DIDIdentity, verify_did_proof

try:
    from zkp_privacy import (
        create_speed_limit_proof,
        pedersen_privacy_metadata,
        verify_speed_limit_proof,
        create_location_ownership_proof,
        verify_location_ownership_proof,
    )
except Exception:
    from zkp_privacy import (
        create_speed_limit_proof,
        pedersen_privacy_metadata,
        verify_speed_limit_proof,
        create_location_ownership_proof,
        verify_location_ownership_proof,
    )

try:
    from anomaly_detector import LightweightAnomalyDetector
except Exception:
    from anomaly_detector import LightweightAnomalyDetector

try:
    from smart_contracts import DynamicSmartContractEngine
except Exception:
    from smart_contracts import DynamicSmartContractEngine

try:
    from edge_layer import EdgeTelemetryLayer
except Exception:
    from edge_layer import EdgeTelemetryLayer

try:
    from perf_metrics import log_zkp_latency
except Exception:
    from perf_metrics import log_zkp_latency

try:
    from federated_learning import FederatedObstacleLearner, fl_validation_metadata
except Exception:
    from federated_learning import FederatedObstacleLearner, fl_validation_metadata

try:
    from security_capabilities import (
        adversarial_validation_metadata,
        complexity_boundary_metadata,
        contribution_boundary_metadata,
        reviewer_audit_metadata,
    )
except Exception:
    from security_capabilities import (
        adversarial_validation_metadata,
        complexity_boundary_metadata,
        contribution_boundary_metadata,
        reviewer_audit_metadata,
    )

load_project_env_once()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('SmartCarBlockchain')

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AESGCM_AVAILABLE = True
except Exception:
    AESGCM = None
    _AESGCM_AVAILABLE = False

CONSENSUS_POA = "POA"
CONSENSUS_POP_POA = "POA_POP"
DEFAULT_POA_AUTHORITY_ID = "authority_node_1"
DEFAULT_POA_AUTHORITY_KEY = "SmartCarPoAKey_2024_Node1"

# ============================================================
# SHA2 / SHA3 Hash Utilities
# ============================================================

def sha2_256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def sha2_512(data: str) -> str:
    return hashlib.sha512(data.encode()).hexdigest()

def sha3_256(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()

def sha3_512(data: str) -> str:
    return hashlib.sha3_512(data.encode()).hexdigest()

def dual_hash(data: str) -> Dict[str, str]:
    """Compute both SHA2-256 and SHA3-256"""
    return {
        'sha2': sha2_256(data),
        'sha3': sha3_256(data),
        'combined': sha2_256(data + sha3_256(data))  # chained hash
    }

def compute_block_hash(index: int, timestamp: str, vehicle_id: str,
                       telemetry_hash_sha3: str, event_hash_sha3: str,
                       previous_hash: str) -> str:
    """Main block hash: sha3_256(index+timestamp+vehicle_id+telemetry_hash+event_hash+previous_hash)"""
    raw = f"{index}{timestamp}{vehicle_id}{telemetry_hash_sha3}{event_hash_sha3}{previous_hash}"
    return sha3_256(raw)


def poa_sign_block(block_hash: str, validator_id: str, authority_round: int, validator_key: str) -> str:
    payload = f"{block_hash}|{validator_id}|{authority_round}"
    return hmac.new(validator_key.encode(), payload.encode(), hashlib.sha256).hexdigest()

# ============================================================
# Encryption (AES-256 equivalent using PBKDF2 + XOR stream)
# For real deployment, use cryptography library AES-GCM
# ============================================================

class SmartCarCrypto:
    """Symmetric encryption using PBKDF2-derived key + HMAC authentication"""

    def __init__(self, password: str, salt: bytes = None):
        self.salt = salt or secrets.token_bytes(32)
        self.key = hashlib.pbkdf2_hmac('sha256', password.encode(), self.salt, 100_000, dklen=64)
        self.enc_key = self.key[:32]
        self.mac_key = self.key[32:]

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        """Generate keystream using SHA3-256 CTR mode"""
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = sha3_256(nonce.hex() + str(counter)).encode()
            # XOR key into stream
            for i, b in enumerate(bytes.fromhex(sha3_256(self.enc_key.hex() + nonce.hex() + str(counter)))):
                stream.append(b)
            counter += 1
        return bytes(stream[:length])

    def encrypt(self, plaintext: str) -> str:
        """Encrypt + authenticate, returns base64 encoded package"""
        data = plaintext.encode()
        nonce = secrets.token_bytes(16)
        keystream = self._keystream(nonce, len(data))
        ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
        # HMAC-SHA256 authentication tag
        mac = hmac.new(self.mac_key, nonce + ciphertext, hashlib.sha256).digest()
        package = nonce + mac + ciphertext
        return base64.b64encode(package).decode()

    def decrypt(self, encrypted_b64: str) -> Optional[str]:
        """Decrypt and verify HMAC, returns None if tampered"""
        try:
            package = base64.b64decode(encrypted_b64)
            nonce = package[:16]
            mac = package[16:48]
            ciphertext = package[48:]
            # Verify HMAC
            expected_mac = hmac.new(self.mac_key, nonce + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                logger.warning("HMAC verification FAILED - data tampered!")
                return None
            keystream = self._keystream(nonce, len(ciphertext))
            plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
            return plaintext.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

    def get_salt_hex(self) -> str:
        return self.salt.hex()


class LocalStorageCipher:
    """Encrypt/decrypt blockchain persistence payload for at-rest protection."""

    def __init__(self, passphrase: str, iterations: int = 200_000):
        self.passphrase = passphrase
        self.iterations = iterations
        self.aad = b"SMARTCAR_CHAIN_SECURE_V1"

    def _derive_key(self, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            self.passphrase.encode(),
            salt,
            self.iterations,
            dklen=32
        )

    def encrypt_payload(self, payload: Dict) -> Dict:
        """Return encrypted envelope for JSON-serializable payload."""
        plaintext = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
        if _AESGCM_AVAILABLE:
            salt = secrets.token_bytes(16)
            nonce = secrets.token_bytes(12)
            key = self._derive_key(salt)
            ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), self.aad)
            return {
                'format': 'SMARTCAR_CHAIN_SECURE_V1',
                'encrypted': True,
                'cipher': 'AES-256-GCM',
                'kdf': 'PBKDF2-HMAC-SHA256',
                'iterations': self.iterations,
                'salt_b64': base64.b64encode(salt).decode(),
                'nonce_b64': base64.b64encode(nonce).decode(),
                'ciphertext_b64': base64.b64encode(ciphertext).decode(),
                'saved_at': datetime.now(timezone.utc).isoformat()
            }

        # Fallback for environments without cryptography package.
        fallback_salt = secrets.token_bytes(32)
        fallback_crypto = SmartCarCrypto(self.passphrase, salt=fallback_salt)
        ciphertext = fallback_crypto.encrypt(plaintext)
        return {
            'format': 'SMARTCAR_CHAIN_SECURE_V1',
            'encrypted': True,
            'cipher': 'PBKDF2-SHA256-STREAM-HMAC',
            'kdf': 'PBKDF2-HMAC-SHA256',
            'iterations': 100_000,
            'salt_b64': base64.b64encode(fallback_salt).decode(),
            'ciphertext_b64': ciphertext,
            'saved_at': datetime.now(timezone.utc).isoformat()
        }


class TimeWindowCircularBuffer:
    """Fixed-size circular buffer with time-window snapshot selection."""

    def __init__(self, capacity: int, window_seconds: int):
        self.capacity = max(64, int(capacity))
        self.window_seconds = max(60, int(window_seconds))
        self._buf: List[Optional[Dict[str, Any]]] = [None] * self.capacity
        self._write_idx = 0
        self._count = 0

    def append(self, sample: Dict[str, Any]):
        self._buf[self._write_idx] = sample
        self._write_idx = (self._write_idx + 1) % self.capacity
        self._count = min(self.capacity, self._count + 1)

    def snapshot(self, now_ts: datetime) -> List[Dict[str, Any]]:
        if self._count == 0:
            return []
        cutoff = now_ts.timestamp() - self.window_seconds
        start = (self._write_idx - self._count) % self.capacity
        out: List[Dict[str, Any]] = []
        for i in range(self._count):
            idx = (start + i) % self.capacity
            item = self._buf[idx]
            if not item:
                continue
            ts = ForensicBlackboxLogger._safe_ts(item.get("timestamp", ""))
            if ts.timestamp() >= cutoff:
                out.append(item)
        return out


class ForensicBlackboxLogger:
    """Capture rolling raw data and lock it in an encrypted forensic package on critical events."""

    def __init__(
        self,
        vehicle_id: str,
        forensic_access_key: str,
        insurance_access_key: str,
        window_seconds: int = 600,
        sample_hz: int = 2,
        key_wrap_iterations: int = 250_000,
    ):
        self.vehicle_id = vehicle_id
        self.window_seconds = max(60, int(window_seconds))
        self.key_wrap_iterations = max(100_000, int(key_wrap_iterations))
        self.forensic_access_key = forensic_access_key
        self.insurance_access_key = insurance_access_key
        self._lock = threading.Lock()
        capacity = max(128, self.window_seconds * max(1, int(sample_hz)))
        self._samples = TimeWindowCircularBuffer(capacity=capacity, window_seconds=self.window_seconds)

    def add_sample(self, timestamp: str, event: str, telemetry: Dict[str, Any], source: str = "runtime"):
        with self._lock:
            self._samples.append(
                {
                    "timestamp": timestamp,
                    "event": event,
                    "source": source,
                    "telemetry": dict(telemetry),
                }
            )

    def create_locked_package(
        self,
        trigger_event: str,
        trigger_type: str,
        trigger_timestamp: str,
        reference_block_hash: str = "",
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            ts = self._safe_ts(trigger_timestamp)
            samples = self._samples.snapshot(ts)
            if not samples:
                return None

        raw_payload = {
            "format": "SMARTCAR_FORENSIC_BLACKBOX_V1",
            "vehicle_id": self.vehicle_id,
            "trigger_event": trigger_event,
            "trigger_type": trigger_type,
            "trigger_timestamp": trigger_timestamp,
            "reference_block_hash": reference_block_hash,
            "window_seconds": self.window_seconds,
            "sample_count": len(samples),
            "samples": samples,
        }
        plaintext = json.dumps(raw_payload, separators=(",", ":"), ensure_ascii=False)
        payload_hash = sha3_256(plaintext)
        data_key = secrets.token_bytes(32)

        encrypted_payload = self._encrypt_payload(plaintext, data_key)
        if encrypted_payload is None:
            return None

        return {
            "format": "SMARTCAR_FORENSIC_LOCKED_PACKAGE_V1",
            "locked": True,
            "payload_hash_sha3": payload_hash,
            "sample_count": len(samples),
            "window_start": samples[0].get("timestamp", "") if samples else "",
            "window_end": samples[-1].get("timestamp", "") if samples else "",
            "key_wrap_kdf": "PBKDF2-HMAC-SHA256",
            "key_wrap_iterations": self.key_wrap_iterations,
            "encrypted_payload": encrypted_payload,
            "key_recipients": {
                "forensic_team": self._wrap_data_key(data_key, self.forensic_access_key),
                "insurance_company": self._wrap_data_key(data_key, self.insurance_access_key),
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _encrypt_payload(self, plaintext: str, data_key: bytes) -> Optional[Dict[str, Any]]:
        if _AESGCM_AVAILABLE:
            nonce = secrets.token_bytes(12)
            aad = b"SMARTCAR_BLACKBOX_PAYLOAD_V1"
            ciphertext = AESGCM(data_key).encrypt(nonce, plaintext.encode(), aad)
            return {
                "cipher": "AES-256-GCM",
                "aad": base64.b64encode(aad).decode(),
                "nonce_b64": base64.b64encode(nonce).decode(),
                "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            }

        fallback = SmartCarCrypto(base64.b64encode(data_key).decode())
        return {
            "cipher": "PBKDF2-SHA256-STREAM-HMAC",
            "ciphertext_b64": fallback.encrypt(plaintext),
            "fallback_note": "Install cryptography for AES-256-GCM payload encryption.",
        }

    def _wrap_data_key(self, data_key: bytes, recipient_key: str) -> Dict[str, Any]:
        recipient = recipient_key or "SMARTCAR_DEFAULT_FORENSIC_ACCESS"
        if _AESGCM_AVAILABLE:
            salt = secrets.token_bytes(16)
            nonce = secrets.token_bytes(12)
            wrap_key = hashlib.pbkdf2_hmac(
                "sha256",
                recipient.encode(),
                salt,
                self.key_wrap_iterations,
                dklen=32,
            )
            aad = b"SMARTCAR_BLACKBOX_KEY_WRAP_V1"
            wrapped = AESGCM(wrap_key).encrypt(nonce, data_key, aad)
            return {
                "cipher": "AES-256-GCM",
                "salt_b64": base64.b64encode(salt).decode(),
                "nonce_b64": base64.b64encode(nonce).decode(),
                "aad": base64.b64encode(aad).decode(),
                "wrapped_key_b64": base64.b64encode(wrapped).decode(),
            }

        fallback = SmartCarCrypto(recipient)
        return {
            "cipher": "PBKDF2-SHA256-STREAM-HMAC",
            "salt_hex": fallback.get_salt_hex(),
            "wrapped_key_b64": fallback.encrypt(base64.b64encode(data_key).decode()),
            "fallback_note": "Install cryptography for AES-256-GCM key wrapping.",
        }

    @staticmethod
    def _safe_ts(ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

# ============================================================
# Data Structures
# ============================================================

@dataclass
class TelemetryData:
    speed: float = 0.0              # km/h
    acceleration: float = 0.0      # m/sÂ²
    fuel_level: float = 100.0      # %
    battery_voltage: float = 12.6  # V
    engine_temp: float = 20.0      # Â°C
    gps_lat: float = 0.0
    gps_lon: float = 0.0
    obstacle_distance: float = 999.0  # meters (999 = no obstacle)
    emergency_brake_active: bool = False
    steering_angle: float = 0.0    # degrees
    brake_pressure: float = 0.0    # %
    throttle_position: float = 0.0 # %
    rpm: float = 0.0
    odometer: float = 0.0          # km
    driver_heart_rate_bpm: float = 72.0
    driver_drowsiness_score: float = 0.0
    driver_unwell: bool = False
    timestamp: str = ""

    def to_string(self) -> str:
        return (f"{self.speed},{self.acceleration},{self.fuel_level},"
                f"{self.battery_voltage},{self.engine_temp},"
                f"{self.gps_lat},{self.gps_lon},{self.obstacle_distance},"
                f"{self.emergency_brake_active},{self.steering_angle},"
                f"{self.brake_pressure},{self.throttle_position},"
                f"{self.rpm},{self.odometer},"
                f"{self.driver_heart_rate_bpm},{self.driver_drowsiness_score},{self.driver_unwell},"
                f"{self.timestamp}")

@dataclass
class Block:
    index: int
    timestamp: str
    vehicle_id: str
    telemetry: TelemetryData
    event_data: str
    previous_hash: str

    # Hash fields
    telemetry_hash_sha2: str = ""
    telemetry_hash_sha3: str = ""
    event_hash_sha2: str = ""
    event_hash_sha3: str = ""
    block_hash: str = ""
    dual_hash_combined: str = ""
    encrypted_dual_hash: str = ""

    # Status
    is_valid: bool = True
    emergency_brake_triggered: bool = False
    block_signature: str = ""  # HMAC of block_hash
    consensus: str = CONSENSUS_POA
    validator_id: str = ""
    authority_round: int = 0
    poa_signature: str = ""
    privacy_preserving: bool = False
    zkp_proofs: Dict[str, Dict] = field(default_factory=dict)
    anomaly_detected: bool = False
    anomaly_score: float = 0.0
    anomaly_threshold: float = 0.0
    anomaly_reasons: List[str] = field(default_factory=list)
    smart_contract_receipts: List[Dict] = field(default_factory=list)
    edge_processed: bool = False
    edge_summary: Dict = field(default_factory=dict)
    forensic_blackbox_locked: bool = False
    forensic_blackbox_payload: Dict = field(default_factory=dict)
    biometric_hash_sha3: str = ""
    safe_mode_activated: bool = False
    fl_model_update_shared: bool = False
    fl_model_update_payload: Dict = field(default_factory=dict)
    archived_pruned: bool = False
    archive_shard_id: str = ""
    archive_root_hash: str = ""
    pop_required: bool = False
    pop_approved: bool = False
    pop_reason: str = ""
    pop_proof_hash: str = ""
    pop_window_observations: List[Dict[str, Any]] = field(default_factory=list)
    pop_distance_min_m: float = 0.0
    pop_distance_max_m: float = 0.0

    def compute_hashes(self, crypto: SmartCarCrypto = None,
                       poa_validator_key: str = ""):
        tel_str = self.telemetry.to_string()
        self.telemetry_hash_sha2 = sha2_256(tel_str)
        self.telemetry_hash_sha3 = sha3_256(tel_str)
        self.event_hash_sha2 = sha2_256(self.event_data)
        self.event_hash_sha3 = sha3_256(self.event_data)
        self.block_hash = compute_block_hash(
            self.index, self.timestamp, self.vehicle_id,
            self.telemetry_hash_sha3, self.event_hash_sha3, self.previous_hash
        )
        self.dual_hash_combined = sha2_256(self.block_hash) + ":" + sha3_256(self.block_hash)
        biometric_raw = (
            f"{self.telemetry.driver_heart_rate_bpm:.2f}|"
            f"{self.telemetry.driver_drowsiness_score:.4f}|"
            f"{int(bool(self.telemetry.driver_unwell))}"
        )
        self.biometric_hash_sha3 = sha3_256(biometric_raw)
        if crypto:
            self.encrypted_dual_hash = crypto.encrypt(self.dual_hash_combined)
            # Sign block with HMAC
            self.block_signature = hmac.new(
                crypto.mac_key, self.block_hash.encode(), hashlib.sha256
            ).hexdigest()
        if poa_validator_key and self.validator_id:
            self.poa_signature = poa_sign_block(
                self.block_hash,
                self.validator_id,
                self.authority_round,
                poa_validator_key
            )

    def verify(self, crypto: SmartCarCrypto = None, poa_validator_key: str = "") -> bool:
        """Verify block integrity"""
        # Recompute hashes
        tel_str = self.telemetry.to_string()
        if sha3_256(tel_str) != self.telemetry_hash_sha3:
            return False
        if sha2_256(tel_str) != self.telemetry_hash_sha2:
            return False
        expected_hash = compute_block_hash(
            self.index, self.timestamp, self.vehicle_id,
            self.telemetry_hash_sha3, self.event_hash_sha3, self.previous_hash
        )
        if expected_hash != self.block_hash:
            return False
        expected_bio_hash = sha3_256(
            f"{self.telemetry.driver_heart_rate_bpm:.2f}|"
            f"{self.telemetry.driver_drowsiness_score:.4f}|"
            f"{int(bool(self.telemetry.driver_unwell))}"
        )
        if self.biometric_hash_sha3 and self.biometric_hash_sha3 != expected_bio_hash:
            return False
        # Verify encrypted dual hash if crypto provided
        if crypto and self.encrypted_dual_hash:
            decrypted = crypto.decrypt(self.encrypted_dual_hash)
            if decrypted is None:
                return False
            expected_dual = sha2_256(self.block_hash) + ":" + sha3_256(self.block_hash)
            if decrypted != expected_dual:
                return False
        if self.consensus == CONSENSUS_POA:
            if not (self.validator_id and self.poa_signature):
                return False
            if not poa_validator_key:
                return False
            expected_poa_sig = poa_sign_block(
                self.block_hash,
                self.validator_id,
                self.authority_round,
                poa_validator_key
            )
            if not hmac.compare_digest(self.poa_signature, expected_poa_sig):
                return False
        return True

    def to_dict(self) -> dict:
        d = {
            'index': self.index,
            'timestamp': self.timestamp,
            'vehicle_id': self.vehicle_id,
            'event_data': self.event_data,
            'previous_hash': self.previous_hash,
            'telemetry_hash_sha2': self.telemetry_hash_sha2,
            'telemetry_hash_sha3': self.telemetry_hash_sha3,
            'event_hash_sha2': self.event_hash_sha2,
            'event_hash_sha3': self.event_hash_sha3,
            'block_hash': self.block_hash,
            'dual_hash_combined': self.dual_hash_combined,
            'encrypted_dual_hash': self.encrypted_dual_hash,
            'block_signature': self.block_signature,
            'consensus': self.consensus,
            'validator_id': self.validator_id,
            'authority_round': self.authority_round,
            'poa_signature': self.poa_signature,
            'privacy_preserving': self.privacy_preserving,
            'zkp_proofs': self.zkp_proofs,
            'anomaly_detected': self.anomaly_detected,
            'anomaly_score': self.anomaly_score,
            'anomaly_threshold': self.anomaly_threshold,
            'anomaly_reasons': self.anomaly_reasons,
            'smart_contract_receipts': self.smart_contract_receipts,
            'edge_processed': self.edge_processed,
            'edge_summary': self.edge_summary,
            'forensic_blackbox_locked': self.forensic_blackbox_locked,
            'forensic_blackbox_payload': self.forensic_blackbox_payload,
            'biometric_hash_sha3': self.biometric_hash_sha3,
            'safe_mode_activated': self.safe_mode_activated,
            'fl_model_update_shared': self.fl_model_update_shared,
            'fl_model_update_payload': self.fl_model_update_payload,
            'archived_pruned': self.archived_pruned,
            'archive_shard_id': self.archive_shard_id,
            'archive_root_hash': self.archive_root_hash,
            'pop_required': self.pop_required,
            'pop_approved': self.pop_approved,
            'pop_reason': self.pop_reason,
            'pop_proof_hash': self.pop_proof_hash,
            'pop_window_observations': self.pop_window_observations,
            'pop_distance_min_m': self.pop_distance_min_m,
            'pop_distance_max_m': self.pop_distance_max_m,
            'is_valid': self.is_valid,
            'emergency_brake_triggered': self.emergency_brake_triggered,
            'telemetry': asdict(self.telemetry),
        }
        return d

# ============================================================
# SmartCar Blockchain
# ============================================================

EMERGENCY_BRAKE_DISTANCE = 100.0  # meters

class SmartCarBlockchain:
    def __init__(self, vehicle_id: str, password: str, auth_token: str,
                 chain_file: str = None,
                 validator_id: str = None,
                 validator_key: str = None,
                 authority_registry: Optional[Dict[str, str]] = None,
                 speed_limit_kmh: int = 120):
        self.vehicle_id = vehicle_id
        self.crypto = SmartCarCrypto(password)
        self.authorized_hash = sha3_256(auth_token)
        self.chain: List[Block] = []
        self.chain_file = chain_file or f"logs/blockchain_{vehicle_id}.json"
        self._lock = threading.Lock()
        self.pop_enabled = get_bool("SMARTCAR_PLATOON_POP_ENABLED", False)
        self.consensus = CONSENSUS_POP_POA if self.pop_enabled else CONSENSUS_POA

        validator_id = validator_id or get_env("SMARTCAR_VALIDATOR_ID", DEFAULT_POA_AUTHORITY_ID)
        validator_key = validator_key or get_env("SMARTCAR_VALIDATOR_KEY", DEFAULT_POA_AUTHORITY_KEY)
        self.authority_registry: Dict[str, str] = dict(authority_registry or {})
        if validator_id not in self.authority_registry:
            self.authority_registry[validator_id] = validator_key
        self.validator_id = validator_id
        self.validator_key = self.authority_registry[validator_id]
        self.authority_order = sorted(self.authority_registry.keys())
        self.did_identity = DIDIdentity.generate(vehicle_id=self.vehicle_id)
        self.did_document = self.did_identity.to_document()
        self.speed_limit_kmh = get_int("SMARTCAR_SPEED_LIMIT_KMH", speed_limit_kmh)
        self.anomaly_detector = LightweightAnomalyDetector(window_size=30, threshold=3.0)
        self.smart_contract_engine = DynamicSmartContractEngine()
        self.fl_enabled = get_bool("SMARTCAR_FL_ENABLED", True)
        self.fl_update_min_interval_sec = float(get_env("SMARTCAR_FL_UPDATE_INTERVAL_SEC", "8.0"))
        self.fl_round_cooldown_ts = 0.0
        self.fl_learner = FederatedObstacleLearner(vehicle_id=self.vehicle_id)
        self.fl_learner.learning_rate = float(get_env("SMARTCAR_FL_LEARNING_RATE", "0.05"))
        self.fl_learner.local_epochs = int(get_env("SMARTCAR_FL_LOCAL_EPOCHS", "3"))
        self.fl_learner.min_samples_per_update = int(get_env("SMARTCAR_FL_MIN_SAMPLES", "12"))
        self.fl_learner.dp_enabled = get_bool("SMARTCAR_FL_DP_ENABLED", True)
        self.fl_learner.dp_noise_sigma = float(get_env("SMARTCAR_FL_DP_NOISE_SIGMA", "0.010"))
        self.fl_learner.delta_clip_norm = float(get_env("SMARTCAR_FL_DELTA_CLIP_NORM", "0.25"))
        self.fl_learner.remote_delta_max_norm = float(get_env("SMARTCAR_FL_REMOTE_DELTA_MAX_NORM", "0.65"))
        self.pruning_enabled = get_bool("SMARTCAR_PRUNING_ENABLED", True)
        self.prune_keep_recent_blocks = get_int("SMARTCAR_PRUNE_KEEP_RECENT_BLOCKS", 200)
        self.prune_batch_size = get_int("SMARTCAR_PRUNE_BATCH_SIZE", 50)
        self.archive_node_file = get_env(
            "SMARTCAR_ARCHIVE_NODE_FILE",
            f"logs/archive_{self.vehicle_id}.jsonl"
        )
        self.archive_shards_meta: List[Dict[str, Any]] = []
        self.shard_sync_enabled = get_bool("SMARTCAR_SHARD_SYNC_ENABLED", True)
        self.shard_sync_max_anchors = max(64, get_int("SMARTCAR_SHARD_SYNC_MAX_ANCHORS", 1024))
        self.shard_sync_bundle_file = get_env(
            "SMARTCAR_SHARD_SYNC_BUNDLE_FILE",
            f"logs/shard_sync_bundle_{self.vehicle_id}.json"
        )
        self.remote_shard_anchors: Dict[str, Dict[str, Any]] = {}
        self.remote_checkpoints: Dict[str, Dict[str, Any]] = {}
        self.checkpoint_enabled = get_bool("SMARTCAR_CHECKPOINT_ENABLED", True)
        self.checkpoint_every_n_shards = max(1, get_int("SMARTCAR_CHECKPOINT_EVERY_N_SHARDS", 1))
        self.checkpoint_min_interval_sec = float(get_env("SMARTCAR_CHECKPOINT_MIN_INTERVAL_SEC", "8.0"))
        self.checkpoint_file = get_env(
            "SMARTCAR_CHECKPOINT_FILE",
            f"logs/state_checkpoint_{self.vehicle_id}.json"
        )
        self.checkpoint_history_file = get_env(
            "SMARTCAR_CHECKPOINT_HISTORY_FILE",
            f"logs/state_checkpoint_history_{self.vehicle_id}.jsonl"
        )
        self.latest_checkpoint_meta: Dict[str, Any] = {}
        self._last_checkpoint_ts = 0.0
        self.auto_storage_management_enabled = get_bool("SMARTCAR_AUTO_STORAGE_MANAGEMENT_ENABLED", True)
        self.storage_min_free_mb = float(get_env("SMARTCAR_STORAGE_MIN_FREE_MB", "512"))
        self.storage_min_free_percent = float(get_env("SMARTCAR_STORAGE_MIN_FREE_PERCENT", "8.0"))
        self.storage_critical_free_mb = float(get_env("SMARTCAR_STORAGE_CRITICAL_FREE_MB", "256"))
        self.storage_critical_free_percent = float(get_env("SMARTCAR_STORAGE_CRITICAL_FREE_PERCENT", "4.0"))
        self.storage_prune_multiplier = max(1, get_int("SMARTCAR_STORAGE_PRUNE_BATCH_MULTIPLIER", 2))
        self.storage_critical_prune_multiplier = max(
            self.storage_prune_multiplier,
            get_int("SMARTCAR_STORAGE_CRITICAL_PRUNE_BATCH_MULTIPLIER", 4),
        )
        self.pop_distance_min_m = float(get_env("SMARTCAR_POP_DISTANCE_MIN_M", "5.0"))
        self.pop_distance_max_m = float(get_env("SMARTCAR_POP_DISTANCE_MAX_M", "55.0"))
        self.pop_observation_ttl_sec = float(get_env("SMARTCAR_POP_OBSERVATION_TTL_SEC", "1.5"))
        self.pop_required_participants = get_int("SMARTCAR_POP_REQUIRED_PARTICIPANTS", 2)
        self.pop_min_confidence = float(get_env("SMARTCAR_POP_MIN_CONFIDENCE", "0.80"))
        self._pop_observations: Dict[str, Dict[str, Any]] = {}
        self.edge_enabled = get_env("SMARTCAR_EDGE_ENABLED", "1") == "1"
        self.edge_window_size = get_int("SMARTCAR_EDGE_WINDOW_SIZE", 5)
        self.edge_flush_interval_sec = float(get_env("SMARTCAR_EDGE_FLUSH_INTERVAL_SEC", "2.0"))
        self.edge_forensic_queue_size = get_int("SMARTCAR_EDGE_FORENSIC_QUEUE_SIZE", 2400)
        self.edge_layer = EdgeTelemetryLayer(
            enabled=self.edge_enabled,
            window_size=self.edge_window_size,
            flush_interval_sec=self.edge_flush_interval_sec,
            forensic_queue_size=self.edge_forensic_queue_size,
            forensic_window_sec=get_int("SMARTCAR_EDGE_FORENSIC_WINDOW_SEC", 600),
        )
        self.storage_encryption_enabled = get_bool("SMARTCAR_STORAGE_ENCRYPTION", True)
        self.storage_passphrase = get_env("SMARTCAR_STORAGE_PASSPHRASE", password)
        self.storage_cipher = LocalStorageCipher(
            passphrase=self.storage_passphrase,
            iterations=get_int("SMARTCAR_STORAGE_KDF_ITERATIONS", 200_000)
        )
        self.owner_recovery_key = get_env("SMARTCAR_OWNER_RECOVERY_KEY", auth_token)
        self.owner_recovery_hash = sha3_256(self.owner_recovery_key)
        self.owner_allow_chain_reset = get_bool("SMARTCAR_OWNER_ALLOW_CHAIN_RESET", True)
        self.blackbox_window_sec = get_int("SMARTCAR_BLACKBOX_WINDOW_SEC", 600)
        self.forensic_access_key = get_env("SMARTCAR_FORENSIC_ACCESS_KEY", password)
        self.insurance_access_key = get_env("SMARTCAR_INSURANCE_ACCESS_KEY", password)
        self.blackbox_logger = ForensicBlackboxLogger(
            vehicle_id=self.vehicle_id,
            forensic_access_key=self.forensic_access_key,
            insurance_access_key=self.insurance_access_key,
            window_seconds=self.blackbox_window_sec,
            sample_hz=get_int("SMARTCAR_BLACKBOX_SAMPLE_HZ", 2),
            key_wrap_iterations=get_int("SMARTCAR_BLACKBOX_KDF_ITERATIONS", 250_000),
        )
        self.biometric_drowsy_threshold = float(get_env("BIOMETRIC_DROWSINESS_THRESHOLD", "0.80"))
        if get_env("SMARTCAR_OWNER_RECOVERY_KEY", "").strip() == "":
            logger.warning(
                "SMARTCAR_OWNER_RECOVERY_KEY à¦¨à¦¾ à¦¥à¦¾à¦•à¦¾à§Ÿ auth token fallback recovery key à¦¹à¦¿à¦¸à§‡à¦¬à§‡ à¦¬à§à¦¯à¦¬à¦¹à§ƒà¦¤ à¦¹à¦šà§à¦›à§‡. "
                "Production à¦ à¦†à¦²à¦¾à¦¦à¦¾ à¦¶à¦•à§à¦¤à¦¿à¦¶à¦¾à¦²à§€ recovery key à¦¸à§‡à¦Ÿ à¦•à¦°à§à¦¨."
            )
        if get_env("SMARTCAR_FORENSIC_ACCESS_KEY", "").strip() == "":
            logger.warning("SMARTCAR_FORENSIC_ACCESS_KEY missing. Password fallback is active.")
        if get_env("SMARTCAR_INSURANCE_ACCESS_KEY", "").strip() == "":
            logger.warning("SMARTCAR_INSURANCE_ACCESS_KEY missing. Password fallback is active.")

        # Vehicle state
        self.car_unlocked = False
        self.engine_started = False
        self.emergency_brake_active = False
        self.safe_mode_active = False
        self.failed_auth_attempts = 0
        self.MAX_FAILED_AUTHS = 3
        self.locked_out = False
        self._last_forensic_block_ts = 0.0
        self.forensic_block_cooldown_sec = float(get_env("SMARTCAR_FORENSIC_BLOCK_COOLDOWN_SEC", "3.0"))
        self._logged_speed_violation_blocks: set[int] = set()

        # Create genesis
        self._create_genesis()
        self._maybe_create_checkpoint(reason="GENESIS_BOOTSTRAP", force=True)
        logger.info(
            f"SmartCar Blockchain initialized for vehicle: {vehicle_id} | "
            f"consensus={self.consensus} | validator={self.validator_id} | "
            f"edge_enabled={self.edge_enabled} | storage_encryption={self.storage_encryption_enabled}"
        )

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _blackbox_trigger_type(self, event_data: str, telemetry: TelemetryData, reasons: List[str]) -> str:
        event_upper = event_data.upper()
        if (
            "CHAIN_COMPROMISED" in event_upper
            or "CHAIN_FAIL" in event_upper
            or "AUTH:FAIL" in event_upper
            or "LOCKOUT" in event_upper
            or "HACK" in event_upper
            or "FORENSIC:TRIGGER" in event_upper
            or "security_block" in reasons
            or "chain_integrity_threat" in reasons
        ):
            return "HACKING_OR_SECURITY_BREACH"
        if (
            telemetry.obstacle_distance <= 30.0
            or telemetry.emergency_brake_active
            or "EMERGENCY" in event_upper
            or "COLLISION" in event_upper
            or "IMPACT" in event_upper
            or "CRASH" in event_upper
        ):
            return "PHYSICAL_IMPACT"
        return ""

    def submit_proximity_observation(
        self,
        peer_vehicle_id: str,
        distance_m: float,
        confidence: float = 0.95,
        sensor: str = "LIDAR",
    ):
        """
        Record one recent peer proximity observation for Proof-of-Proximity consensus.
        Expected source: V2V / platoon lidar exchange.
        """
        if not peer_vehicle_id:
            return
        self._pop_observations[peer_vehicle_id] = {
            "peer_vehicle_id": peer_vehicle_id,
            "distance_m": float(distance_m),
            "confidence": float(confidence),
            "sensor": sensor,
            "timestamp": self._now(),
            "observed_ts": time.time(),
        }

    def _is_pop_relevant_event(self, event: str) -> bool:
        ev = str(event).upper()
        return (
            "TELEMETRY" in ev
            or "LIVE_SEC_MONITOR" in ev
            or "V2V:" in ev
            or "V2X:" in ev
            or "PLATOON" in ev
        )

    def _get_recent_pop_observations(self) -> List[Dict[str, Any]]:
        now = time.time()
        cutoff = now - self.pop_observation_ttl_sec
        stale = [k for k, v in self._pop_observations.items() if float(v.get("observed_ts", 0.0)) < cutoff]
        for k in stale:
            self._pop_observations.pop(k, None)
        return list(self._pop_observations.values())

    def _build_pop_proof_hash(
        self,
        index: int,
        timestamp: str,
        event_data: str,
        own_distance_m: float,
        selected_obs: List[Dict[str, Any]],
    ) -> str:
        payload = {
            "index": int(index),
            "timestamp": str(timestamp),
            "vehicle_id": self.vehicle_id,
            "event_data": str(event_data),
            "own_distance_m": round(float(own_distance_m), 4),
            "distance_min_m": self.pop_distance_min_m,
            "distance_max_m": self.pop_distance_max_m,
            "selected_observations": [
                {
                    "peer_vehicle_id": str(x.get("peer_vehicle_id", "")),
                    "distance_m": round(float(x.get("distance_m", 0.0)), 4),
                    "confidence": round(float(x.get("confidence", 0.0)), 4),
                    "sensor": str(x.get("sensor", "")),
                    "timestamp": str(x.get("timestamp", "")),
                } for x in selected_obs
            ],
        }
        return sha3_256(json.dumps(payload, sort_keys=True, separators=(",", ":")))

    def _evaluate_pop_consensus(self, index: int, timestamp: str, event_data: str, telemetry: TelemetryData) -> Dict[str, Any]:
        own_distance = float(telemetry.obstacle_distance)
        own_valid = self.pop_distance_min_m <= own_distance <= self.pop_distance_max_m
        observations = self._get_recent_pop_observations()
        selected = []
        for obs in observations:
            d = float(obs.get("distance_m", 9999.0))
            c = float(obs.get("confidence", 0.0))
            if self.pop_distance_min_m <= d <= self.pop_distance_max_m and c >= self.pop_min_confidence:
                selected.append(obs)
        participants = (1 if own_valid else 0) + len(selected)
        approved = own_valid and participants >= max(1, int(self.pop_required_participants))
        reason = "POP_APPROVED" if approved else (
            "POP_FAIL_OWN_DISTANCE_OUT_OF_RANGE" if not own_valid else "POP_FAIL_INSUFFICIENT_NEIGHBOR_CONFIRMATION"
        )
        return {
            "required": True,
            "approved": approved,
            "reason": reason,
            "participants": participants,
            "own_distance_m": own_distance,
            "selected_observations": selected,
            "proof_hash": self._build_pop_proof_hash(index, timestamp, event_data, own_distance, selected),
        }

    def _is_forensic_impact_trigger(self, event: str, telemetry: TelemetryData) -> bool:
        ev = event.upper()
        return (
            "IMPACT" in ev
            or "COLLISION" in ev
            or "CRASH" in ev
            or "EMERGENCY" in ev
            or telemetry.emergency_brake_active
            or telemetry.obstacle_distance <= 30.0
        )

    def _maybe_push_forensic_block(self, trigger_event: str):
        now = time.time()
        if now - self._last_forensic_block_ts < self.forensic_block_cooldown_sec:
            return
        bundle = self.edge_layer.build_forensic_block(trigger_event=trigger_event, reason="IMPACT")
        if not bundle:
            return
        s = bundle["telemetry"]
        forensic_tel = TelemetryData(
            speed=float(s.get("speed", 0.0)),
            acceleration=float(s.get("acceleration", 0.0)),
            fuel_level=float(s.get("fuel_level", 100.0)),
            battery_voltage=float(s.get("battery_voltage", 12.6)),
            engine_temp=float(s.get("engine_temp", 20.0)),
            gps_lat=float(s.get("gps_lat", 0.0)),
            gps_lon=float(s.get("gps_lon", 0.0)),
            obstacle_distance=float(s.get("obstacle_distance", 999.0)),
            emergency_brake_active=bool(s.get("emergency_brake_active", False)),
            steering_angle=float(s.get("steering_angle", 0.0)),
            brake_pressure=float(s.get("brake_pressure", 0.0)),
            throttle_position=float(s.get("throttle_position", 0.0)),
            rpm=float(s.get("rpm", 0.0)),
            odometer=float(s.get("odometer", 0.0)),
            driver_heart_rate_bpm=float(s.get("driver_heart_rate_bpm", 72.0)),
            driver_drowsiness_score=float(s.get("driver_drowsiness_score", 0.0)),
            driver_unwell=bool(s.get("driver_unwell", False)),
            timestamp=str(s.get("timestamp", self._now())),
        )
        self._add_block(forensic_tel, bundle["event"], edge_meta=bundle.get("meta", {}))
        self._last_forensic_block_ts = now

    def _maybe_publish_fl_update(self, telemetry: TelemetryData, event: str):
        if not self.fl_enabled:
            return
        now = time.time()
        if now - self.fl_round_cooldown_ts < self.fl_update_min_interval_sec:
            return
        event_upper = str(event).upper()
        trigger_for_round = (
            telemetry.obstacle_distance <= 40.0
            or telemetry.emergency_brake_active
            or "OBSTACLE" in event_upper
            or "EMERGENCY" in event_upper
            or "IMPACT" in event_upper
        )
        if not trigger_for_round:
            return

        update = self.fl_learner.maybe_create_local_update(trigger_event=event)
        if update is None:
            return

        payload = update.to_dict()
        fl_event = f"FL:MODEL_UPDATE:ROUND_{payload.get('round_id', 0)}"
        self._add_block(telemetry, fl_event, edge_meta={"fl_update": payload, "fl_publish": True})
        self.fl_round_cooldown_ts = now

    def apply_remote_fl_update(self, update_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply model-weight delta received from another vehicle and persist aggregation event on-chain.
        """
        result = self.fl_learner.apply_remote_update(update_payload)
        if not result.get("applied"):
            return result

        tel = TelemetryData(timestamp=self._now())
        src = str(update_payload.get("vehicle_id", "unknown"))
        round_id = int(update_payload.get("round_id", 0))
        agg_event = f"FL:AGGREGATE_UPDATE:FROM_{src}:ROUND_{round_id}"
        self._add_block(
            tel,
            agg_event,
            edge_meta={
                "fl_remote_update": dict(update_payload),
                "fl_aggregation_result": dict(result),
            }
        )
        return result

    def apply_global_fl_model(self, global_model_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply trainer-published global model weights.
        """
        return self.apply_remote_fl_update(global_model_payload)

    def _activate_safe_mode(self, reason: str = "UNKNOWN"):
        self.safe_mode_active = True
        self.emergency_brake_active = True
        logger.warning("SAFE MODE activated: %s", reason)

    def clear_safe_mode(self):
        self.safe_mode_active = False
        self.emergency_brake_active = False

    def _archive_shard_root(self, blocks: List[Block]) -> str:
        if not blocks:
            return ""
        leaf_hashes = [
            sha3_256(
                f"{b.index}|{b.block_hash}|{b.telemetry_hash_sha3}|{b.event_hash_sha3}|{b.previous_hash}"
            ) for b in blocks
        ]
        level = list(leaf_hashes)
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(sha3_256(left + right))
            level = nxt
        return level[0]

    @staticmethod
    def _anchor_key(source_vehicle_id: str, shard_id: str) -> str:
        return f"{source_vehicle_id}::{shard_id}"

    def _canonical_anchor_payload(self, anchor: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source_vehicle_id": str(anchor.get("source_vehicle_id", "")),
            "shard_id": str(anchor.get("shard_id", "")),
            "root_hash_sha3": str(anchor.get("root_hash_sha3", "")),
            "block_index_start": int(anchor.get("block_index_start", 0)),
            "block_index_end": int(anchor.get("block_index_end", 0)),
            "block_count": int(anchor.get("block_count", 0)),
            "created_at": str(anchor.get("created_at", "")),
            "validator_id": str(anchor.get("validator_id", "")),
            "checkpoint_hash_sha3": str(anchor.get("checkpoint_hash_sha3", "")),
        }

    def _build_signed_shard_anchor(self, shard_meta: Dict[str, Any], checkpoint_hash: str = "") -> Dict[str, Any]:
        payload = self._canonical_anchor_payload({
            "source_vehicle_id": self.vehicle_id,
            "shard_id": shard_meta.get("shard_id", ""),
            "root_hash_sha3": shard_meta.get("root_hash_sha3", ""),
            "block_index_start": shard_meta.get("block_index_start", 0),
            "block_index_end": shard_meta.get("block_index_end", 0),
            "block_count": shard_meta.get("block_count", 0),
            "created_at": shard_meta.get("created_at", ""),
            "validator_id": self.validator_id,
            "checkpoint_hash_sha3": checkpoint_hash,
        })
        anchor_hash = sha3_256(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        anchor_sig = poa_sign_block(
            anchor_hash,
            validator_id=self.validator_id,
            authority_round=int(payload["block_index_end"]),
            validator_key=self.validator_key,
        )
        payload["anchor_hash_sha3"] = anchor_hash
        payload["anchor_signature"] = anchor_sig
        return payload

    def _verify_signed_shard_anchor(self, anchor: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(anchor, dict):
            return {"valid": False, "reason": "anchor_invalid_type"}
        payload = self._canonical_anchor_payload(anchor)
        anchor_hash = str(anchor.get("anchor_hash_sha3", ""))
        anchor_sig = str(anchor.get("anchor_signature", ""))
        validator = str(payload.get("validator_id", ""))
        if not anchor_hash or not anchor_sig or not validator:
            return {"valid": False, "reason": "anchor_missing_fields"}
        expected_hash = sha3_256(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        if not hmac.compare_digest(anchor_hash, expected_hash):
            return {"valid": False, "reason": "anchor_hash_mismatch"}
        validator_key = self.authority_registry.get(validator, "")
        if not validator_key:
            return {"valid": False, "reason": "anchor_unknown_validator"}
        expected_sig = poa_sign_block(
            anchor_hash,
            validator_id=validator,
            authority_round=int(payload.get("block_index_end", 0)),
            validator_key=validator_key,
        )
        if not hmac.compare_digest(anchor_sig, expected_sig):
            return {"valid": False, "reason": "anchor_signature_invalid"}
        return {"valid": True, "reason": "ok", "payload": payload}

    @staticmethod
    def _archive_leaf_hash_from_dict(block_dict: Dict[str, Any]) -> str:
        return sha3_256(
            f"{block_dict.get('index', 0)}|"
            f"{block_dict.get('block_hash', '')}|"
            f"{block_dict.get('telemetry_hash_sha3', '')}|"
            f"{block_dict.get('event_hash_sha3', '')}|"
            f"{block_dict.get('previous_hash', '')}"
        )

    @staticmethod
    def _build_merkle_proof(leaf_hashes: List[str], target_index: int) -> List[Dict[str, str]]:
        if not leaf_hashes or target_index < 0 or target_index >= len(leaf_hashes):
            return []
        proof: List[Dict[str, str]] = []
        idx = target_index
        level = list(leaf_hashes)
        while len(level) > 1:
            if idx % 2 == 0:
                sibling_idx = idx + 1 if idx + 1 < len(level) else idx
                sibling_pos = "R"
            else:
                sibling_idx = idx - 1
                sibling_pos = "L"
            proof.append({"position": sibling_pos, "hash": level[sibling_idx]})
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(sha3_256(left + right))
            idx //= 2
            level = nxt
        return proof

    @staticmethod
    def _verify_merkle_proof(leaf_hash: str, proof: List[Dict[str, str]], root_hash: str) -> bool:
        current = str(leaf_hash)
        for step in proof:
            pos = str(step.get("position", "")).upper()
            sibling = str(step.get("hash", ""))
            if not sibling:
                return False
            if pos == "L":
                current = sha3_256(sibling + current)
            else:
                current = sha3_256(current + sibling)
        return hmac.compare_digest(current, str(root_hash))

    def _write_archive_shard(self, shard: Dict[str, Any]):
        Path(os.path.dirname(self.archive_node_file) or ".").mkdir(parents=True, exist_ok=True)
        with open(self.archive_node_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(shard, ensure_ascii=False) + "\n")

    def _compact_archived_block(self, b: Block, shard_id: str, root_hash: str):
        b.archived_pruned = True
        b.archive_shard_id = shard_id
        b.archive_root_hash = root_hash
        b.zkp_proofs = {}
        b.smart_contract_receipts = []
        b.edge_summary = {}
        b.forensic_blackbox_payload = {}
        b.anomaly_reasons = []
        b.fl_model_update_payload = {}
        b.telemetry = TelemetryData(timestamp=b.timestamp)
        # Keep event marker lightweight for dashboard/history scan.
        if not str(b.event_data).startswith("ARCHIVED:SHARD:"):
            b.event_data = f"ARCHIVED:SHARD:{shard_id}:BLOCK_{b.index}"

    def _archive_file_size_bytes(self) -> int:
        try:
            return int(Path(self.archive_node_file).stat().st_size)
        except Exception:
            return 0

    def _storage_health(self) -> Dict[str, float]:
        target_dir = os.path.dirname(self.chain_file) or "."
        try:
            usage = shutil.disk_usage(target_dir)
            total = float(usage.total)
            free = float(usage.free)
        except Exception:
            total = 0.0
            free = 0.0
        free_mb = free / (1024.0 * 1024.0) if free > 0 else 0.0
        free_pct = (free / total * 100.0) if total > 0 else 0.0
        return {
            "free_mb": round(free_mb, 2),
            "free_percent": round(free_pct, 2),
            "archive_file_mb": round(self._archive_file_size_bytes() / (1024.0 * 1024.0), 2),
        }

    def _storage_pressure_level(self) -> str:
        health = self._storage_health()
        free_mb = health["free_mb"]
        free_pct = health["free_percent"]
        if free_mb <= self.storage_critical_free_mb or free_pct <= self.storage_critical_free_percent:
            return "critical"
        if free_mb <= self.storage_min_free_mb or free_pct <= self.storage_min_free_percent:
            return "low"
        return "normal"

    def _make_state_checkpoint(self, reason: str) -> Dict[str, Any]:
        active_blocks = sum(1 for b in self.chain if not b.archived_pruned)
        archived_blocks = sum(1 for b in self.chain if b.archived_pruned)
        latest = self.chain[-1]
        payload: Dict[str, Any] = {
            "format": "SMARTCAR_STATE_CHECKPOINT_V1",
            "vehicle_id": self.vehicle_id,
            "created_at": self._now(),
            "reason": reason,
            "chain_length": len(self.chain),
            "latest_block_index": latest.index,
            "latest_block_hash": latest.block_hash,
            "latest_timestamp": latest.timestamp,
            "active_blocks": active_blocks,
            "archived_compacted_blocks": archived_blocks,
            "archive_shards_count": len(self.archive_shards_meta),
            "archive_roots": [m.get("root_hash_sha3", "") for m in self.archive_shards_meta[-256:]],
            "authority_order": list(self.authority_order),
            "validator_id": self.validator_id,
            "did": self.did_document.get("id", ""),
            "fl_round_id": self.fl_learner.snapshot().get("round_id", 0),
            "consensus": self.consensus,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload["checkpoint_hash_sha3"] = sha3_256(canonical)
        payload["checkpoint_signature"] = poa_sign_block(
            payload["checkpoint_hash_sha3"],
            validator_id=self.validator_id,
            authority_round=latest.index,
            validator_key=self.validator_key,
        )
        return payload

    def _write_checkpoint(self, checkpoint: Dict[str, Any]):
        Path(os.path.dirname(self.checkpoint_file) or ".").mkdir(parents=True, exist_ok=True)
        Path(os.path.dirname(self.checkpoint_history_file) or ".").mkdir(parents=True, exist_ok=True)
        with open(self.checkpoint_file, "w", encoding="utf-8") as f:
            json.dump(checkpoint, f, indent=2)
        with open(self.checkpoint_history_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(checkpoint, ensure_ascii=False) + "\n")

    def _maybe_create_checkpoint(self, reason: str, force: bool = False) -> Optional[Dict[str, Any]]:
        if not self.checkpoint_enabled:
            return None
        if not force:
            now = time.time()
            if now - self._last_checkpoint_ts < self.checkpoint_min_interval_sec:
                return None
            if len(self.archive_shards_meta) == 0:
                return None
            if len(self.archive_shards_meta) % self.checkpoint_every_n_shards != 0:
                return None
        checkpoint = self._make_state_checkpoint(reason=reason)
        self._write_checkpoint(checkpoint)
        self.latest_checkpoint_meta = {
            "checkpoint_hash_sha3": checkpoint.get("checkpoint_hash_sha3", ""),
            "latest_block_index": checkpoint.get("latest_block_index", 0),
            "latest_block_hash": checkpoint.get("latest_block_hash", ""),
            "created_at": checkpoint.get("created_at", ""),
            "reason": checkpoint.get("reason", ""),
        }
        self._last_checkpoint_ts = time.time()
        return checkpoint

    def _prune_and_archive_if_needed(self, batch_multiplier: int = 1, reason: str = "policy"):
        if not self.pruning_enabled:
            return
        keep_recent = max(20, int(self.prune_keep_recent_blocks))
        if len(self.chain) <= keep_recent + 1:
            return
        prune_upto_exclusive = max(1, len(self.chain) - keep_recent)
        candidates = [b for b in self.chain[1:prune_upto_exclusive] if not b.archived_pruned]
        if not candidates:
            return
        eff_batch = max(1, int(self.prune_batch_size) * max(1, int(batch_multiplier)))
        batch = candidates[:eff_batch]
        shard_id = f"shard_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:8]}"
        root_hash = self._archive_shard_root(batch)
        checkpoint_hash = str(self.load_latest_checkpoint().get("checkpoint_hash_sha3", ""))
        shard_payload = {
            "format": "SMARTCAR_ARCHIVE_SHARD_V1",
            "shard_id": shard_id,
            "vehicle_id": self.vehicle_id,
            "created_at": self._now(),
            "block_index_start": batch[0].index,
            "block_index_end": batch[-1].index,
            "block_count": len(batch),
            "root_hash_sha3": root_hash,
            "checkpoint_hash_sha3": checkpoint_hash,
            "prune_reason": reason,
            "blocks": [b.to_dict() for b in batch],
        }
        signed_anchor = self._build_signed_shard_anchor(
            {
                "shard_id": shard_id,
                "root_hash_sha3": root_hash,
                "block_index_start": batch[0].index,
                "block_index_end": batch[-1].index,
                "block_count": len(batch),
                "created_at": shard_payload["created_at"],
            },
            checkpoint_hash=checkpoint_hash,
        )
        shard_payload["signed_anchor"] = dict(signed_anchor)
        self._write_archive_shard(shard_payload)
        self.archive_shards_meta.append({
            "shard_id": shard_id,
            "root_hash_sha3": root_hash,
            "block_index_start": batch[0].index,
            "block_index_end": batch[-1].index,
            "block_count": len(batch),
            "created_at": shard_payload["created_at"],
            "prune_reason": reason,
            "checkpoint_hash_sha3": checkpoint_hash,
            "anchor_hash_sha3": signed_anchor.get("anchor_hash_sha3", ""),
            "anchor_signature": signed_anchor.get("anchor_signature", ""),
            "validator_id": self.validator_id,
            "source_vehicle_id": self.vehicle_id,
        })
        for b in batch:
            self._compact_archived_block(b, shard_id=shard_id, root_hash=root_hash)
        self._maybe_create_checkpoint(reason=f"PRUNE:{reason}", force=True)

    def _create_genesis(self):
        genesis_tel = TelemetryData(timestamp=self._now())
        authority_round = 0
        expected_validator = self._expected_validator(0)
        if expected_validator != self.validator_id:
            raise RuntimeError(
                f"Validator mismatch for genesis. expected={expected_validator} actual={self.validator_id}"
            )
        genesis = Block(
            index=0,
            timestamp=self._now(),
            vehicle_id=self.vehicle_id,
            telemetry=genesis_tel,
            event_data="GENESIS:VEHICLE_INITIALIZED",
            previous_hash="0" * 64,
            consensus=self.consensus,
            validator_id=self.validator_id,
            authority_round=authority_round
        )
        genesis.privacy_preserving = True
        genesis.compute_hashes(self.crypto, self.validator_key)
        self.chain.append(genesis)
        logger.info(f"Genesis block: {genesis.block_hash[:32]}...")

    def _expected_validator(self, block_index: int) -> str:
        if not self.authority_order:
            raise RuntimeError("No PoA authorities configured")
        return self.authority_order[block_index % len(self.authority_order)]

    def _add_block(self, telemetry: TelemetryData, event: str, edge_meta: Optional[Dict] = None) -> Block:
        with self._lock:
            prev = self.chain[-1]
            authority_round = len(self.chain)
            expected_validator = self._expected_validator(authority_round)
            if expected_validator != self.validator_id:
                raise RuntimeError(
                    f"PoA authority mismatch. expected={expected_validator} actual={self.validator_id}"
                )
            block = Block(
                index=len(self.chain),
                timestamp=self._now(),
                vehicle_id=self.vehicle_id,
                telemetry=telemetry,
                event_data=event,
                previous_hash=prev.block_hash,
                consensus=self.consensus,
                validator_id=self.validator_id,
                authority_round=authority_round
            )
            if self.pop_enabled and self._is_pop_relevant_event(event):
                pop_res = self._evaluate_pop_consensus(
                    index=block.index,
                    timestamp=block.timestamp,
                    event_data=block.event_data,
                    telemetry=telemetry,
                )
                block.pop_required = True
                block.pop_approved = bool(pop_res.get("approved", False))
                block.pop_reason = str(pop_res.get("reason", "POP_UNKNOWN"))
                block.pop_proof_hash = str(pop_res.get("proof_hash", ""))
                block.pop_window_observations = list(pop_res.get("selected_observations", []))
                block.pop_distance_min_m = self.pop_distance_min_m
                block.pop_distance_max_m = self.pop_distance_max_m
                if not block.pop_approved:
                    block.event_data = f"PLATOON:BLOCKED:POP_FAIL:{block.pop_reason}|{block.event_data}"
            block.privacy_preserving = True
            block.edge_processed = bool(edge_meta)
            block.edge_summary = dict(edge_meta or {})
            # Check emergency brake
            if (
                telemetry.obstacle_distance < EMERGENCY_BRAKE_DISTANCE
                and self.engine_started
                and not str(block.event_data).upper().startswith("FORENSIC_BLOCK:")
                and not str(block.event_data).upper().startswith("FL:")
                and "PLATOON:BLOCKED:POP_FAIL" not in str(block.event_data).upper()
            ):
                block.emergency_brake_triggered = True
                self.emergency_brake_active = True
                block.event_data = (f"EMERGENCY:BRAKE_TRIGGERED:"
                                    f"OBSTACLE_{telemetry.obstacle_distance:.1f}M")

            telemetry_payload = {
                "speed": telemetry.speed,
                "acceleration": telemetry.acceleration,
                "engine_temp": telemetry.engine_temp,
                "rpm": telemetry.rpm,
                "obstacle_distance": telemetry.obstacle_distance,
                "driver_heart_rate_bpm": telemetry.driver_heart_rate_bpm,
                "driver_drowsiness_score": telemetry.driver_drowsiness_score,
                "driver_unwell": telemetry.driver_unwell,
            }
            telem_anomaly = self.anomaly_detector.detect_telemetry(telemetry_payload)
            sec_anomaly = self.anomaly_detector.detect_security_event(
                event=block.event_data,
                failed_auth_attempts=self.failed_auth_attempts
            )
            block.anomaly_detected = telem_anomaly.is_anomaly or sec_anomaly.is_anomaly
            block.anomaly_score = max(telem_anomaly.score, sec_anomaly.score)
            block.anomaly_threshold = self.anomaly_detector.threshold
            block.anomaly_reasons = sorted(set(telem_anomaly.reasons + sec_anomaly.reasons))
            if block.anomaly_detected and "ANOMALY:DETECTED" not in block.event_data:
                reason_txt = ",".join(block.anomaly_reasons[:3]) if block.anomaly_reasons else "unknown"
                block.event_data = f"{block.event_data}|ANOMALY:DETECTED:{reason_txt}"

            if block.pop_required:
                block.pop_proof_hash = self._build_pop_proof_hash(
                    index=block.index,
                    timestamp=block.timestamp,
                    event_data=block.event_data,
                    own_distance_m=telemetry.obstacle_distance,
                    selected_obs=block.pop_window_observations,
                )

            block.compute_hashes(self.crypto, self.validator_key)
            if str(block.event_data).upper().startswith("FL:MODEL_UPDATE:"):
                block.fl_model_update_shared = True
                if isinstance(edge_meta, dict):
                    block.fl_model_update_payload = dict(edge_meta.get("fl_update", {}))
            trigger_type = self._blackbox_trigger_type(
                event_data=block.event_data,
                telemetry=telemetry,
                reasons=block.anomaly_reasons,
            )
            if trigger_type:
                locked_package = self.blackbox_logger.create_locked_package(
                    trigger_event=block.event_data,
                    trigger_type=trigger_type,
                    trigger_timestamp=block.timestamp,
                    reference_block_hash=block.block_hash,
                )
                if locked_package:
                    block.forensic_blackbox_locked = True
                    block.forensic_blackbox_payload = locked_package
            proof_ctx = f"{block.vehicle_id}|{block.index}|{block.timestamp}|{block.block_hash}"
            t0 = time.perf_counter()
            speed_proof = create_speed_limit_proof(
                telemetry.speed,
                self.speed_limit_kmh,
                proof_ctx
            )
            log_zkp_latency(
                operation="speed_limit",
                phase="generate",
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                extra={"block_index": block.index, "vehicle_id": self.vehicle_id}
            )
            t1 = time.perf_counter()
            loc_proof = create_location_ownership_proof(
                telemetry.gps_lat,
                telemetry.gps_lon,
                proof_ctx
            )
            log_zkp_latency(
                operation="location_ownership",
                phase="generate",
                latency_ms=(time.perf_counter() - t1) * 1000.0,
                extra={"block_index": block.index, "vehicle_id": self.vehicle_id}
            )
            block.zkp_proofs = {
                "speed_limit": speed_proof,
                "location_ownership": loc_proof,
            }
            block.smart_contract_receipts = self.smart_contract_engine.evaluate_and_invoke(
                vehicle_id=self.vehicle_id,
                did=self.did_document.get("id", ""),
                event_data=block.event_data,
                telemetry={
                    "speed": telemetry.speed,
                    "acceleration": telemetry.acceleration,
                    "engine_temp": telemetry.engine_temp,
                    "rpm": telemetry.rpm,
                    "gps_lat": telemetry.gps_lat,
                    "gps_lon": telemetry.gps_lon,
                    "obstacle_distance": telemetry.obstacle_distance,
                    "driver_heart_rate_bpm": telemetry.driver_heart_rate_bpm,
                    "driver_drowsiness_score": telemetry.driver_drowsiness_score,
                    "driver_unwell": telemetry.driver_unwell,
                },
                block_hash=block.block_hash
            )
            if any(str(r.get("action", "")).upper() == "SAFE_MODE_ACTIVATE" for r in block.smart_contract_receipts):
                self._activate_safe_mode(reason="biometric_contract_rule")
                block.safe_mode_activated = True
            self.chain.append(block)
            self._maybe_auto_storage_prune()
            self._prune_and_archive_if_needed()
            return block

    def _maybe_auto_storage_prune(self):
        if not self.auto_storage_management_enabled or not self.pruning_enabled:
            return
        pressure = self._storage_pressure_level()
        if pressure == "critical":
            self._prune_and_archive_if_needed(
                batch_multiplier=self.storage_critical_prune_multiplier,
                reason="storage_critical",
            )
            self._maybe_create_checkpoint(reason="STORAGE:CRITICAL", force=True)
            return
        if pressure == "low":
            self._prune_and_archive_if_needed(
                batch_multiplier=self.storage_prune_multiplier,
                reason="storage_low",
            )

    # ---- Authentication ----

    def authenticate(self, token: str) -> Dict:
        if self.locked_out:
            return {'success': False, 'reason': 'LOCKOUT_ACTIVE_TOO_MANY_FAILURES'}

        token_hash = sha3_256(token)

        if not hmac.compare_digest(token_hash, self.authorized_hash):
            self.failed_auth_attempts += 1
            event = f"AUTH:FAIL:INVALID_TOKEN:ATTEMPT_{self.failed_auth_attempts}"
            self._add_block(TelemetryData(timestamp=self._now()), event)
            if self.failed_auth_attempts >= self.MAX_FAILED_AUTHS:
                self.locked_out = True
                self._add_block(TelemetryData(timestamp=self._now()),
                               "SECURITY:LOCKOUT_ACTIVATED")
            logger.warning(f"Auth failed. Attempt {self.failed_auth_attempts}/{self.MAX_FAILED_AUTHS}")
            return {'success': False, 'reason': 'INVALID_TOKEN',
                    'attempts': self.failed_auth_attempts}

        # Check chain integrity before unlocking
        if not self.verify_chain():
            self._add_block(TelemetryData(timestamp=self._now()),
                           "AUTH:BLOCKED:CHAIN_COMPROMISED")
            logger.error("Chain integrity fail - car stays locked!")
            return {'success': False, 'reason': 'CHAIN_INTEGRITY_COMPROMISED'}

        self.car_unlocked = True
        self.failed_auth_attempts = 0
        self._add_block(TelemetryData(timestamp=self._now()), "AUTH:SUCCESS")
        logger.info("Authentication SUCCESS - car unlocked")
        return {'success': True, 'reason': 'AUTHENTICATED'}

    def start_engine(self) -> Dict:
        if not self.car_unlocked:
            return {'success': False, 'reason': 'NOT_AUTHENTICATED'}
        if not self.verify_chain():
            self.car_unlocked = False
            self._add_block(TelemetryData(timestamp=self._now()),
                           "ENGINE:BLOCKED:CHAIN_FAIL")
            return {'success': False, 'reason': 'CHAIN_INTEGRITY_FAIL'}
        self.engine_started = True
        self._add_block(TelemetryData(timestamp=self._now()), "ENGINE:STARTED")
        logger.info("Engine STARTED")
        return {'success': True}

    def stop_engine(self) -> Dict:
        self.flush_edge_to_chain("EDGE:FLUSH:ENGINE_STOP")
        self.engine_started = False
        self.clear_safe_mode()
        self._add_block(TelemetryData(timestamp=self._now()), "ENGINE:STOPPED")
        return {'success': True}

    def lock_car(self):
        self.flush_edge_to_chain("EDGE:FLUSH:LOCK")
        self.car_unlocked = False
        self.engine_started = False
        self.clear_safe_mode()
        self._add_block(TelemetryData(timestamp=self._now()), "VEHICLE:LOCKED")

    def _reset_chain_to_genesis(self):
        """Reset chain to fresh genesis for owner-approved recovery."""
        self.chain = []
        self._create_genesis()

    def owner_recover_unlock(self, recovery_key: str, force_chain_reset: bool = False) -> Dict:
        """Owner-only recovery unlock flow for lockout/chain-compromise scenarios."""
        if not recovery_key:
            return {'success': False, 'reason': 'EMPTY_RECOVERY_KEY'}

        provided_hash = sha3_256(recovery_key)
        if not hmac.compare_digest(provided_hash, self.owner_recovery_hash):
            self._add_block(TelemetryData(timestamp=self._now()), "RECOVERY:OWNER_FAIL:INVALID_KEY")
            logger.warning("Owner recovery failed: invalid key")
            return {'success': False, 'reason': 'INVALID_RECOVERY_KEY'}

        chain_ok = self.verify_chain()
        if chain_ok:
            self.locked_out = False
            self.failed_auth_attempts = 0
            self.car_unlocked = True
            self.engine_started = False
            self.emergency_brake_active = False
            self.safe_mode_active = False
            self._add_block(TelemetryData(timestamp=self._now()), "RECOVERY:OWNER_UNLOCK:CHAIN_VALID")
            logger.warning("Owner recovery unlock completed (chain valid)")
            return {'success': True, 'mode': 'OWNER_UNLOCK', 'chain_reset': False}

        if not force_chain_reset:
            logger.error("Owner recovery blocked: chain compromised, force reset required")
            return {
                'success': False,
                'reason': 'CHAIN_COMPROMISED_FORCE_RESET_REQUIRED',
                'force_reset_available': self.owner_allow_chain_reset
            }

        if not self.owner_allow_chain_reset:
            logger.error("Owner recovery blocked: chain reset disabled by policy")
            return {'success': False, 'reason': 'CHAIN_RESET_DISABLED'}

        self._reset_chain_to_genesis()
        self.locked_out = False
        self._last_forensic_block_ts = 0.0
        self.failed_auth_attempts = 0
        self.car_unlocked = True
        self.engine_started = False
        self.emergency_brake_active = False
        self.safe_mode_active = False
        self._add_block(TelemetryData(timestamp=self._now()), "RECOVERY:OWNER_UNLOCK:CHAIN_RESET")
        logger.critical("Owner recovery unlock completed with chain reset")
        return {'success': True, 'mode': 'OWNER_RESET_UNLOCK', 'chain_reset': True}

    def push_telemetry(self, telemetry: TelemetryData, event: str = "") -> Block:
        event = event or "TELEMETRY:UPDATE"
        raw = asdict(telemetry)
        self.edge_layer.record_forensic_sample(raw, event_hint=event)
        self.blackbox_logger.add_sample(
            timestamp=telemetry.timestamp or self._now(),
            event=event,
            telemetry=raw,
            source="telemetry_ingest",
        )
        self.fl_learner.ingest_sample(
            telemetry={
                "speed": telemetry.speed,
                "obstacle_distance": telemetry.obstacle_distance,
            },
            event=event,
        )

        urgent = (
            "EMERGENCY" in event.upper()
            or "AUTH:" in event.upper()
            or "ENGINE:" in event.upper()
            or "V2X:" in event.upper()
            or "V2V:" in event.upper()
            or "V2I:" in event.upper()
            or "IMPACT" in event.upper()
            or "COLLISION" in event.upper()
            or "CRASH" in event.upper()
            or "HACK" in event.upper()
            or telemetry.emergency_brake_active
            or telemetry.obstacle_distance <= 30.0
            or telemetry.driver_unwell
            or telemetry.driver_drowsiness_score >= self.biometric_drowsy_threshold
        )

        if not self.edge_enabled or urgent:
            main_block = self._add_block(
                telemetry,
                event,
                edge_meta={"bypass": True, "reason": "urgent" if urgent else "disabled"}
            )
            if self._is_forensic_impact_trigger(main_block.event_data, telemetry):
                self._maybe_push_forensic_block(main_block.event_data)
            self._maybe_publish_fl_update(telemetry, main_block.event_data)
            return main_block

        summary = self.edge_layer.ingest(raw, event_hint=event)
        if summary is None:
            # No chain write yet; return latest committed block for API compatibility.
            return self.chain[-1]

        s = summary["telemetry"]
        summary_tel = TelemetryData(
            speed=s["speed"],
            acceleration=s["acceleration"],
            fuel_level=s["fuel_level"],
            battery_voltage=s["battery_voltage"],
            engine_temp=s["engine_temp"],
            gps_lat=s["gps_lat"],
            gps_lon=s["gps_lon"],
            obstacle_distance=s["obstacle_distance"],
            emergency_brake_active=s["emergency_brake_active"],
            steering_angle=s["steering_angle"],
            brake_pressure=s["brake_pressure"],
            throttle_position=s["throttle_position"],
            rpm=s["rpm"],
            odometer=s["odometer"],
            driver_heart_rate_bpm=s.get("driver_heart_rate_bpm", 0.0),
            driver_drowsiness_score=s.get("driver_drowsiness_score", 0.0),
            driver_unwell=s.get("driver_unwell", False),
            timestamp=s["timestamp"],
        )
        committed = self._add_block(summary_tel, summary["event"], edge_meta=summary.get("meta", {}))
        self._maybe_publish_fl_update(summary_tel, committed.event_data)
        return committed

    def emergency_brake(self, distance: float):
        """Manual emergency brake trigger"""
        tel = TelemetryData(
            obstacle_distance=distance,
            emergency_brake_active=True,
            brake_pressure=100.0,
            throttle_position=0.0,
            timestamp=self._now()
        )
        self.emergency_brake_active = True
        self._add_block(tel, f"EMERGENCY:MANUAL_BRAKE:OBSTACLE_{distance:.1f}M")

    def trigger_forensic_blackbox(self, reason: str, telemetry: Optional[TelemetryData] = None) -> Block:
        """Force-create a forensic blackbox event block."""
        tel = telemetry or TelemetryData(timestamp=self._now())
        return self._add_block(tel, f"FORENSIC:TRIGGER:{reason}")

    def flush_edge_to_chain(self, reason: str = "EDGE:FORCE_FLUSH"):
        if not self.edge_enabled:
            return
        flushed = self.edge_layer.force_flush(reason)
        if not flushed:
            return
        s = flushed["telemetry"]
        summary_tel = TelemetryData(
            speed=s["speed"],
            acceleration=s["acceleration"],
            fuel_level=s["fuel_level"],
            battery_voltage=s["battery_voltage"],
            engine_temp=s["engine_temp"],
            gps_lat=s["gps_lat"],
            gps_lon=s["gps_lon"],
            obstacle_distance=s["obstacle_distance"],
            emergency_brake_active=s["emergency_brake_active"],
            steering_angle=s["steering_angle"],
            brake_pressure=s["brake_pressure"],
            throttle_position=s["throttle_position"],
            rpm=s["rpm"],
            odometer=s["odometer"],
            driver_heart_rate_bpm=s.get("driver_heart_rate_bpm", 0.0),
            driver_drowsiness_score=s.get("driver_drowsiness_score", 0.0),
            driver_unwell=s.get("driver_unwell", False),
            timestamp=s["timestamp"],
        )
        self._add_block(summary_tel, flushed["event"], edge_meta=flushed.get("meta", {}))

    # ---- Verification ----

    @staticmethod
    def _declared_speed_violation_ok(block: Block, speed_proof: Dict[str, Any]) -> bool:
        """
        Accept explicit speed-limit violation marker as a policy violation event,
        not as a chain-integrity failure.
        """
        if not isinstance(speed_proof, dict):
            return False
        if speed_proof.get("scheme") != "COMMITMENT_KNOWLEDGE_LEQ":
            return False
        if bool(speed_proof.get("valid", True)):
            return False
        if str(speed_proof.get("reason", "")).upper() != "SPEED_EXCEEDS_LIMIT":
            return False
        try:
            proof_limit = int(speed_proof.get("limit"))
            block_speed = float(block.telemetry.speed)
        except Exception:
            return False
        return block_speed > float(proof_limit)

    def verify_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i-1]
            if curr.archived_pruned:
                if curr.previous_hash != prev.block_hash:
                    logger.error(f"Archived block {i} chain linkage BROKEN")
                    return False
                continue
            expected_validator = self._expected_validator(curr.index)
            if curr.consensus != self.consensus:
                logger.error(f"Block {i} consensus mismatch")
                return False
            if self.pop_enabled and curr.pop_required:
                proof_expected = self._build_pop_proof_hash(
                    index=curr.index,
                    timestamp=curr.timestamp,
                    event_data=curr.event_data,
                    own_distance_m=curr.telemetry.obstacle_distance,
                    selected_obs=curr.pop_window_observations,
                )
                if curr.pop_proof_hash != proof_expected:
                    logger.error(f"Block {i} PoP proof hash mismatch")
                    return False
                if not curr.pop_approved:
                    if "PLATOON:BLOCKED:POP_FAIL" not in str(curr.event_data).upper():
                        logger.error(f"Block {i} PoP approval missing without blocked marker")
                        return False
            if curr.authority_round != curr.index:
                logger.error(f"Block {i} authority round mismatch")
                return False
            if curr.validator_id != expected_validator:
                logger.error(
                    f"Block {i} validator mismatch expected={expected_validator} actual={curr.validator_id}"
                )
                return False
            poa_key = self.authority_registry.get(curr.validator_id, "")
            if not curr.verify(self.crypto, poa_key):
                logger.error(f"Block {i} verification FAILED")
                return False
            if curr.previous_hash != prev.block_hash:
                logger.error(f"Block {i} chain linkage BROKEN")
                return False
            if curr.privacy_preserving:
                proof_ctx = f"{curr.vehicle_id}|{curr.index}|{curr.timestamp}|{curr.block_hash}"
                speed_proof = curr.zkp_proofs.get("speed_limit", {})
                location_proof = curr.zkp_proofs.get("location_ownership", {})
                t2 = time.perf_counter()
                speed_ok = verify_speed_limit_proof(speed_proof, proof_ctx)
                log_zkp_latency(
                    operation="speed_limit",
                    phase="verify",
                    latency_ms=(time.perf_counter() - t2) * 1000.0,
                    extra={"block_index": curr.index, "vehicle_id": curr.vehicle_id}
                )
                if not speed_ok:
                    if self._declared_speed_violation_ok(curr, speed_proof):
                        if curr.index not in self._logged_speed_violation_blocks:
                            logger.warning(
                                "Block %s speed-limit violation marker accepted (speed=%.2f limit=%s)",
                                i,
                                float(curr.telemetry.speed),
                                speed_proof.get("limit"),
                            )
                            self._logged_speed_violation_blocks.add(curr.index)
                    else:
                        logger.error(f"Block {i} speed privacy proof FAILED")
                        return False
                t3 = time.perf_counter()
                loc_ok = verify_location_ownership_proof(location_proof, proof_ctx)
                log_zkp_latency(
                    operation="location_ownership",
                    phase="verify",
                    latency_ms=(time.perf_counter() - t3) * 1000.0,
                    extra={"block_index": curr.index, "vehicle_id": curr.vehicle_id}
                )
                if not loc_ok:
                    logger.error(f"Block {i} location privacy proof FAILED")
                    return False
        return True

    def verify_and_sync(self) -> Dict:
        valid = self.verify_chain()
        result = {
            'valid': valid,
            'chain_length': len(self.chain),
            'latest_hash': self.chain[-1].block_hash,
            'vehicle_id': self.vehicle_id,
            'timestamp': self._now()
        }
        if not valid:
            self.car_unlocked = False
            self.engine_started = False
        return result

    # ---- Persistence ----

    def save(self):
        """Persist blockchain to disk with optional encryption at rest."""
        self.flush_edge_to_chain("EDGE:FLUSH:SAVE")
        Path(os.path.dirname(self.chain_file) or '.').mkdir(parents=True, exist_ok=True)
        data = {
            'vehicle_id': self.vehicle_id,
            'did_document': self.did_document,
            'privacy_policy': {
                'enabled': True,
                'scheme': 'LIGHTWEIGHT_ZKP_COMMITMENT',
                'speed_limit_kmh': self.speed_limit_kmh
            },
            'ai_anomaly_detection': {
                'enabled': True,
                'model': 'LIGHTWEIGHT_STATISTICAL_ZSCORE',
                'window_size': self.anomaly_detector.window_size,
                'threshold': self.anomaly_detector.threshold
            },
            'smart_contracts': {
                'enabled': self.smart_contract_engine.enabled,
                'mock_mode': self.smart_contract_engine.mock_mode,
                'ethereum_endpoint': self.smart_contract_engine.eth_connector.endpoint,
                'fabric_endpoint': self.smart_contract_engine.fabric_connector.endpoint
            },
            'edge_layer': {
                'enabled': self.edge_enabled,
                'window_size': self.edge_window_size,
                'flush_interval_sec': self.edge_flush_interval_sec,
                'forensic_queue_size': self.edge_forensic_queue_size,
                'forensic_window_sec': self.edge_layer.forensic_window_sec,
            },
            'self_healing': {
                'pruning_enabled': self.pruning_enabled,
                'prune_keep_recent_blocks': self.prune_keep_recent_blocks,
                'prune_batch_size': self.prune_batch_size,
                'archive_node_file': self.archive_node_file,
                'archive_shards_count': len(self.archive_shards_meta),
                'shard_sync_enabled': self.shard_sync_enabled,
                'shard_sync_bundle_file': self.shard_sync_bundle_file,
                'remote_shard_anchor_count': len(self.remote_shard_anchors),
                'checkpoint_enabled': self.checkpoint_enabled,
                'checkpoint_file': self.checkpoint_file,
                'latest_checkpoint_hash': self.latest_checkpoint_meta.get("checkpoint_hash_sha3", ""),
                'auto_storage_management_enabled': self.auto_storage_management_enabled,
                'storage_health': self._storage_health(),
            },
            'platooning_pop': {
                'enabled': self.pop_enabled,
                'consensus': self.consensus,
                'distance_min_m': self.pop_distance_min_m,
                'distance_max_m': self.pop_distance_max_m,
                'observation_ttl_sec': self.pop_observation_ttl_sec,
                'required_participants': self.pop_required_participants,
                'min_confidence': self.pop_min_confidence,
            },
            'archive_shards_meta': list(self.archive_shards_meta),
            'remote_shard_anchors': list(self.remote_shard_anchors.values()),
            'remote_checkpoints': dict(self.remote_checkpoints),
            'state_checkpoint': self.load_latest_checkpoint(),
            'federated_learning': {
                'enabled': self.fl_enabled,
                'update_interval_sec': self.fl_update_min_interval_sec,
                'model': 'LOGISTIC_OBSTACLE_FL_V2',
                'weights': self.fl_learner.snapshot().get('weights', {}),
                'learning_rate': self.fl_learner.learning_rate,
                'local_epochs': self.fl_learner.local_epochs,
                'min_samples_per_update': self.fl_learner.min_samples_per_update,
                'dp_enabled': self.fl_learner.dp_enabled,
                'dp_noise_sigma': self.fl_learner.dp_noise_sigma,
                'delta_clip_norm': self.fl_learner.delta_clip_norm,
                'remote_delta_max_norm': self.fl_learner.remote_delta_max_norm,
            },
            'fl_validation': fl_validation_metadata(),
            'adversarial_validation': adversarial_validation_metadata(),
            'contribution_boundary': contribution_boundary_metadata(),
            'complexity_boundary': complexity_boundary_metadata(),
            'pedersen_privacy': pedersen_privacy_metadata(),
            'reviewer_audit': reviewer_audit_metadata(),
            'forensic_blackbox': {
                'enabled': True,
                'window_seconds': self.blackbox_window_sec,
                'payload_format': 'SMARTCAR_FORENSIC_LOCKED_PACKAGE_V1',
                'recipients': ['forensic_team', 'insurance_company'],
            },
            'biometric_safety': {
                'enabled': True,
                'heart_rate_hash': 'SHA3-256',
                'drowsiness_threshold': self.biometric_drowsy_threshold,
                'auto_safe_mode': True,
            },
            'consensus': self.consensus,
            'validator_id': self.validator_id,
            'authority_order': self.authority_order,
            'authorities': [{'validator_id': vid} for vid in self.authority_order],
            'crypto_salt': self.crypto.get_salt_hex(),
            'authorized_hash': self.authorized_hash,
            'chain': [b.to_dict() for b in self.chain],
            'saved_at': self._now()
        }
        if self.storage_encryption_enabled:
            envelope = self.storage_cipher.encrypt_payload(data)
            with open(self.chain_file, 'w', encoding='utf-8') as f:
                json.dump(envelope, f, indent=2)
            logger.info(
                f"Blockchain saved encrypted: {len(self.chain)} blocks -> {self.chain_file} "
                f"[cipher={envelope.get('cipher')}]"
            )
            if envelope.get('cipher') != 'AES-256-GCM':
                logger.warning(
                    "cryptography package not available; using fallback storage cipher. "
                    "Install 'cryptography' for AES-256-GCM at rest."
                )
        else:
            with open(self.chain_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Blockchain saved plaintext: {len(self.chain)} blocks -> {self.chain_file}")

    def get_status(self) -> Dict:
        return {
            'vehicle_id': self.vehicle_id,
            'did': self.did_document.get('id'),
            'consensus': self.consensus,
            'validator_id': self.validator_id,
            'authority_count': len(self.authority_order),
            'platooning_pop_enabled': self.pop_enabled,
            'pop_distance_min_m': self.pop_distance_min_m,
            'pop_distance_max_m': self.pop_distance_max_m,
            'privacy_preserving': True,
            'speed_limit_kmh': self.speed_limit_kmh,
            'anomaly_detection_enabled': True,
            'smart_contracts_enabled': self.smart_contract_engine.enabled,
            'edge_enabled': self.edge_enabled,
            'edge_window_size': self.edge_window_size,
            'edge_forensic_queue_size': self.edge_forensic_queue_size,
            'blackbox_window_sec': self.blackbox_window_sec,
            'federated_learning_enabled': self.fl_enabled,
            'fl_round_id': self.fl_learner.snapshot().get("round_id", 0),
            'fl_learning_rate': self.fl_learner.learning_rate,
            'fl_local_epochs': self.fl_learner.local_epochs,
            'fl_min_samples_per_update': self.fl_learner.min_samples_per_update,
            'fl_dp_enabled': self.fl_learner.dp_enabled,
            'fl_dp_noise_sigma': self.fl_learner.dp_noise_sigma,
            'fl_delta_clip_norm': self.fl_learner.delta_clip_norm,
            'fl_validation': fl_validation_metadata(),
            'adversarial_validation': adversarial_validation_metadata(),
            'contribution_boundary': contribution_boundary_metadata(),
            'complexity_boundary': complexity_boundary_metadata(),
            'pedersen_privacy': pedersen_privacy_metadata(),
            'reviewer_audit': reviewer_audit_metadata(),
            'pruning_enabled': self.pruning_enabled,
            'archive_shards_count': len(self.archive_shards_meta),
            'archive_node_file': self.archive_node_file,
            'shard_sync_enabled': self.shard_sync_enabled,
            'remote_shard_anchor_count': len(self.remote_shard_anchors),
            'checkpoint_enabled': self.checkpoint_enabled,
            'checkpoint_hash': self.latest_checkpoint_meta.get("checkpoint_hash_sha3", ""),
            'storage_health': self._storage_health(),
            'chain_length': len(self.chain),
            'car_unlocked': self.car_unlocked,
            'engine_started': self.engine_started,
            'emergency_brake_active': self.emergency_brake_active,
            'safe_mode_active': self.safe_mode_active,
            'locked_out': self.locked_out,
            'failed_auth_attempts': self.failed_auth_attempts,
            'owner_allow_chain_reset': self.owner_allow_chain_reset,
            'chain_valid': self.verify_chain(),
            'latest_hash': self.chain[-1].block_hash,
            'latest_block_index': self.chain[-1].index,
            'latest_event': self.chain[-1].event_data,
            'latest_timestamp': self.chain[-1].timestamp,
            'latest_anomaly_detected': self.chain[-1].anomaly_detected,
            'latest_anomaly_score': self.chain[-1].anomaly_score,
            'latest_contract_invocations': len(self.chain[-1].smart_contract_receipts),
            'latest_blackbox_locked': self.chain[-1].forensic_blackbox_locked,
            'latest_biometric_hash': self.chain[-1].biometric_hash_sha3,
            'latest_safe_mode_activated': self.chain[-1].safe_mode_activated,
            'latest_fl_update_shared': self.chain[-1].fl_model_update_shared,
            'latest_pop_required': self.chain[-1].pop_required,
            'latest_pop_approved': self.chain[-1].pop_approved,
            'latest_pop_reason': self.chain[-1].pop_reason,
        }

    def get_chain_json(self) -> List[Dict]:
        return [b.to_dict() for b in self.chain]

    def get_fl_model_snapshot(self) -> Dict[str, Any]:
        return self.fl_learner.snapshot()

    def get_fl_update_payloads(self, since_block_index: int = 0) -> List[Dict[str, Any]]:
        payloads: List[Dict[str, Any]] = []
        start = max(0, int(since_block_index))
        for b in self.chain[start:]:
            if getattr(b, "fl_model_update_shared", False) and b.fl_model_update_payload:
                payloads.append(dict(b.fl_model_update_payload))
        return payloads

    def load_latest_checkpoint(self) -> Dict[str, Any]:
        if not Path(self.checkpoint_file).exists():
            return {}
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                cp = json.load(f)
            return cp if isinstance(cp, dict) else {}
        except Exception:
            return {}

    def verify_checkpoint_trust(self, checkpoint: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cp = dict(checkpoint or self.load_latest_checkpoint())
        if not cp:
            return {"valid": False, "reason": "checkpoint_missing"}
        cp_hash = str(cp.get("checkpoint_hash_sha3", ""))
        cp_sig = str(cp.get("checkpoint_signature", ""))
        validator = str(cp.get("validator_id", ""))
        if not cp_hash or not cp_sig or not validator:
            return {"valid": False, "reason": "checkpoint_fields_missing"}
        cp_unsigned = dict(cp)
        cp_unsigned.pop("checkpoint_hash_sha3", None)
        cp_unsigned.pop("checkpoint_signature", None)
        expected_hash = sha3_256(json.dumps(cp_unsigned, sort_keys=True, separators=(",", ":")))
        if not hmac.compare_digest(cp_hash, expected_hash):
            return {"valid": False, "reason": "checkpoint_hash_mismatch"}
        validator_key = self.authority_registry.get(validator, "")
        if not validator_key:
            return {"valid": False, "reason": "unknown_validator"}
        expected_sig = poa_sign_block(
            cp_hash,
            validator_id=validator,
            authority_round=int(cp.get("latest_block_index", 0)),
            validator_key=validator_key,
        )
        if not hmac.compare_digest(cp_sig, expected_sig):
            return {"valid": False, "reason": "checkpoint_signature_invalid"}
        return {
            "valid": True,
            "reason": "ok",
            "latest_block_index": int(cp.get("latest_block_index", 0)),
            "latest_block_hash": str(cp.get("latest_block_hash", "")),
            "archive_shards_count": int(cp.get("archive_shards_count", 0)),
            "created_at": str(cp.get("created_at", "")),
        }

    def export_shard_sync_bundle(self, max_anchors: int = 128, write_file: bool = True) -> Dict[str, Any]:
        if not self.shard_sync_enabled:
            return {"ok": False, "reason": "shard_sync_disabled"}
        cap = max(1, min(int(max_anchors), self.shard_sync_max_anchors))
        checkpoint = self.load_latest_checkpoint()
        checkpoint_hash = str(checkpoint.get("checkpoint_hash_sha3", ""))
        anchors: List[Dict[str, Any]] = []
        for meta in self.archive_shards_meta[-cap:]:
            anchors.append(
                self._build_signed_shard_anchor(meta, checkpoint_hash=checkpoint_hash)
            )
        payload = {
            "format": "SMARTCAR_SHARD_SYNC_BUNDLE_V1",
            "source_vehicle_id": self.vehicle_id,
            "validator_id": self.validator_id,
            "generated_at": self._now(),
            "checkpoint": checkpoint,
            "anchors": anchors,
            "anchor_count": len(anchors),
        }
        bundle_hash = sha3_256(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        bundle_sig = poa_sign_block(
            bundle_hash,
            validator_id=self.validator_id,
            authority_round=len(self.chain) - 1,
            validator_key=self.validator_key,
        )
        bundle = dict(payload)
        bundle["bundle_hash_sha3"] = bundle_hash
        bundle["bundle_signature"] = bundle_sig
        if write_file:
            Path(os.path.dirname(self.shard_sync_bundle_file) or ".").mkdir(parents=True, exist_ok=True)
            with open(self.shard_sync_bundle_file, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=2)
        return {"ok": True, "bundle": bundle, "anchor_count": len(anchors)}

    def import_shard_sync_bundle(self, bundle: Dict[str, Any], strict_checkpoint: bool = False) -> Dict[str, Any]:
        b = dict(bundle or {})
        if b.get("format") != "SMARTCAR_SHARD_SYNC_BUNDLE_V1":
            return {"ok": False, "reason": "invalid_bundle_format"}
        bundle_hash = str(b.get("bundle_hash_sha3", ""))
        bundle_sig = str(b.get("bundle_signature", ""))
        source_vehicle = str(b.get("source_vehicle_id", ""))
        validator = str(b.get("validator_id", ""))
        if not bundle_hash or not bundle_sig or not source_vehicle or not validator:
            return {"ok": False, "reason": "bundle_missing_fields"}

        unsigned = dict(b)
        unsigned.pop("bundle_hash_sha3", None)
        unsigned.pop("bundle_signature", None)
        expected_hash = sha3_256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")))
        if not hmac.compare_digest(bundle_hash, expected_hash):
            return {"ok": False, "reason": "bundle_hash_mismatch"}
        validator_key = self.authority_registry.get(validator, "")
        if not validator_key:
            return {"ok": False, "reason": "bundle_unknown_validator"}
        expected_sig = poa_sign_block(
            bundle_hash,
            validator_id=validator,
            authority_round=max(0, int(unsigned.get("checkpoint", {}).get("latest_block_index", 0))),
            validator_key=validator_key,
        )
        if not hmac.compare_digest(bundle_sig, expected_sig):
            return {"ok": False, "reason": "bundle_signature_invalid"}

        checkpoint = unsigned.get("checkpoint", {})
        if isinstance(checkpoint, dict) and checkpoint:
            cp_ok = self.verify_checkpoint_trust(checkpoint)
            if strict_checkpoint and not cp_ok.get("valid"):
                return {"ok": False, "reason": f"checkpoint_invalid:{cp_ok.get('reason', 'unknown')}"}
            self.remote_checkpoints[source_vehicle] = dict(checkpoint)

        imported = 0
        anchors = unsigned.get("anchors", [])
        if not isinstance(anchors, list):
            return {"ok": False, "reason": "bundle_anchors_invalid"}
        for anchor in anchors:
            anchor_ok = self._verify_signed_shard_anchor(anchor)
            if not anchor_ok.get("valid"):
                continue
            payload = anchor_ok["payload"]
            if payload.get("source_vehicle_id") != source_vehicle:
                continue
            key = self._anchor_key(source_vehicle, str(payload.get("shard_id", "")))
            enriched = dict(anchor)
            enriched["imported_at"] = self._now()
            self.remote_shard_anchors[key] = enriched
            imported += 1
        return {
            "ok": True,
            "source_vehicle_id": source_vehicle,
            "imported_anchors": imported,
            "total_remote_anchors": len(self.remote_shard_anchors),
        }

    def _lookup_shard_anchor(self, source_vehicle_id: str, shard_id: str) -> Optional[Dict[str, Any]]:
        if source_vehicle_id == self.vehicle_id:
            meta = next((m for m in self.archive_shards_meta if m.get("shard_id") == shard_id), None)
            if not meta:
                return None
            cp_hash = str(meta.get("checkpoint_hash_sha3", "")) or str(self.load_latest_checkpoint().get("checkpoint_hash_sha3", ""))
            return self._build_signed_shard_anchor(meta, checkpoint_hash=cp_hash)
        return self.remote_shard_anchors.get(self._anchor_key(source_vehicle_id, shard_id))

    def _read_archive_shard(self, shard_id: str) -> Optional[Dict[str, Any]]:
        if not shard_id or not Path(self.archive_node_file).exists():
            return None
        try:
            with open(self.archive_node_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    if str(obj.get("shard_id", "")) == str(shard_id):
                        return obj
        except Exception:
            return None
        return None

    def create_cross_shard_proof(self, shard_id: str, block_index: int) -> Dict[str, Any]:
        shard = self._read_archive_shard(shard_id)
        if not shard:
            return {"ok": False, "reason": "shard_not_found"}
        blocks = shard.get("blocks", [])
        if not isinstance(blocks, list) or not blocks:
            return {"ok": False, "reason": "shard_blocks_missing"}
        target_idx = -1
        for i, blk in enumerate(blocks):
            if int(blk.get("index", -1)) == int(block_index):
                target_idx = i
                break
        if target_idx < 0:
            return {"ok": False, "reason": "block_not_in_shard"}
        leaf_hashes = [self._archive_leaf_hash_from_dict(b) for b in blocks]
        proof = self._build_merkle_proof(leaf_hashes, target_idx)
        block_header = {
            "index": int(blocks[target_idx].get("index", -1)),
            "block_hash": str(blocks[target_idx].get("block_hash", "")),
            "telemetry_hash_sha3": str(blocks[target_idx].get("telemetry_hash_sha3", "")),
            "event_hash_sha3": str(blocks[target_idx].get("event_hash_sha3", "")),
            "previous_hash": str(blocks[target_idx].get("previous_hash", "")),
        }
        checkpoint = self.load_latest_checkpoint()
        checkpoint_hash = str(checkpoint.get("checkpoint_hash_sha3", ""))
        signed_anchor = self._lookup_shard_anchor(self.vehicle_id, str(shard.get("shard_id", ""))) or {}
        return {
            "ok": True,
            "format": "SMARTCAR_CROSS_SHARD_PROOF_V1",
            "vehicle_id": self.vehicle_id,
            "source_vehicle_id": self.vehicle_id,
            "source_shard_id": str(shard.get("shard_id", "")),
            "source_root_hash_sha3": str(shard.get("root_hash_sha3", "")),
            "block_header": block_header,
            "leaf_hash_sha3": leaf_hashes[target_idx],
            "merkle_proof": proof,
            "checkpoint_hash_sha3": checkpoint_hash,
            "signed_anchor": signed_anchor,
            "anchor_hash_sha3": sha3_256(
                f"{self.vehicle_id}|{shard.get('shard_id', '')}|{shard.get('root_hash_sha3', '')}|{checkpoint_hash}"
            ),
            "created_at": self._now(),
        }

    def verify_cross_shard_proof(self, proof_payload: Dict[str, Any]) -> Dict[str, Any]:
        p = dict(proof_payload or {})
        if p.get("format") != "SMARTCAR_CROSS_SHARD_PROOF_V1":
            return {"valid": False, "reason": "invalid_format"}
        source_vehicle_id = str(p.get("source_vehicle_id", p.get("vehicle_id", "")))
        shard_id = str(p.get("source_shard_id", ""))
        root_hash = str(p.get("source_root_hash_sha3", ""))
        block_header = p.get("block_header", {})
        leaf_hash = str(p.get("leaf_hash_sha3", ""))
        merkle_proof = p.get("merkle_proof", [])
        if not source_vehicle_id or not shard_id or not root_hash or not isinstance(block_header, dict):
            return {"valid": False, "reason": "missing_fields"}
        anchor = self._lookup_shard_anchor(source_vehicle_id, shard_id)
        if not anchor:
            return {"valid": False, "reason": "unknown_shard_anchor"}
        anchor_ok = self._verify_signed_shard_anchor(anchor)
        if not anchor_ok.get("valid"):
            return {"valid": False, "reason": f"anchor_invalid:{anchor_ok.get('reason', 'unknown')}"}
        anchor_payload = anchor_ok["payload"]
        if not hmac.compare_digest(str(anchor_payload.get("root_hash_sha3", "")), root_hash):
            return {"valid": False, "reason": "shard_root_mismatch"}
        if not hmac.compare_digest(str(anchor_payload.get("source_vehicle_id", "")), source_vehicle_id):
            return {"valid": False, "reason": "anchor_source_mismatch"}
        expected_leaf = self._archive_leaf_hash_from_dict(block_header)
        if not hmac.compare_digest(expected_leaf, leaf_hash):
            return {"valid": False, "reason": "leaf_hash_mismatch"}
        if not self._verify_merkle_proof(leaf_hash, list(merkle_proof), root_hash):
            return {"valid": False, "reason": "merkle_proof_invalid"}
        return {
            "valid": True,
            "reason": "ok",
            "source_vehicle_id": source_vehicle_id,
            "shard_id": shard_id,
            "block_index": int(block_header.get("index", -1)),
            "root_hash_sha3": root_hash,
        }

    def prune_now(self) -> Dict[str, Any]:
        before = sum(1 for b in self.chain if not b.archived_pruned)
        self._prune_and_archive_if_needed(reason="manual")
        after = sum(1 for b in self.chain if not b.archived_pruned)
        return {
            "pruned": before - after,
            "archive_shards_count": len(self.archive_shards_meta),
            "archive_node_file": self.archive_node_file,
            "latest_checkpoint_hash": self.latest_checkpoint_meta.get("checkpoint_hash_sha3", ""),
        }

    def get_archive_status(self) -> Dict[str, Any]:
        active_blocks = sum(1 for b in self.chain if not b.archived_pruned)
        archived_blocks = sum(1 for b in self.chain if b.archived_pruned)
        return {
            "pruning_enabled": self.pruning_enabled,
            "active_blocks": active_blocks,
            "archived_compacted_blocks": archived_blocks,
            "archive_shards_count": len(self.archive_shards_meta),
            "archive_node_file": self.archive_node_file,
            "latest_archive_root_hash": (self.archive_shards_meta[-1]["root_hash_sha3"] if self.archive_shards_meta else ""),
            "checkpoint_enabled": self.checkpoint_enabled,
            "checkpoint_file": self.checkpoint_file,
            "latest_checkpoint_hash": self.latest_checkpoint_meta.get("checkpoint_hash_sha3", ""),
            "storage_health": self._storage_health(),
            "shard_sync_enabled": self.shard_sync_enabled,
            "local_shard_sync_bundle_file": self.shard_sync_bundle_file,
            "remote_shard_anchor_count": len(self.remote_shard_anchors),
        }

    def get_shard_sync_status(self) -> Dict[str, Any]:
        by_source: Dict[str, int] = {}
        for key in self.remote_shard_anchors.keys():
            source = key.split("::", 1)[0] if "::" in key else "unknown"
            by_source[source] = by_source.get(source, 0) + 1
        return {
            "enabled": self.shard_sync_enabled,
            "max_anchors": self.shard_sync_max_anchors,
            "bundle_file": self.shard_sync_bundle_file,
            "local_anchor_count": len(self.archive_shards_meta),
            "remote_anchor_count": len(self.remote_shard_anchors),
            "remote_sources": by_source,
            "remote_checkpoint_count": len(self.remote_checkpoints),
        }

    def get_checkpoint_status(self) -> Dict[str, Any]:
        latest = self.load_latest_checkpoint()
        verification = self.verify_checkpoint_trust(latest) if latest else {"valid": False, "reason": "checkpoint_missing"}
        return {
            "enabled": self.checkpoint_enabled,
            "checkpoint_file": self.checkpoint_file,
            "checkpoint_history_file": self.checkpoint_history_file,
            "latest": latest,
            "verification": verification,
        }

    def get_pop_status(self) -> Dict[str, Any]:
        recent = self._get_recent_pop_observations()
        return {
            "enabled": self.pop_enabled,
            "consensus": self.consensus,
            "distance_min_m": self.pop_distance_min_m,
            "distance_max_m": self.pop_distance_max_m,
            "required_participants": self.pop_required_participants,
            "min_confidence": self.pop_min_confidence,
            "recent_observation_count": len(recent),
            "recent_observations": recent[-10:],
        }

    def get_public_chain_json(self) -> List[Dict]:
        public_chain = []
        for b in self.chain:
            d = b.to_dict()
            if "telemetry" in d:
                d["telemetry"]["speed"] = None
                d["telemetry"]["gps_lat"] = None
                d["telemetry"]["gps_lon"] = None
                d["telemetry"]["driver_heart_rate_bpm"] = None
                d["telemetry"]["driver_drowsiness_score"] = None
                d["telemetry"]["driver_unwell"] = None
            if d.get("forensic_blackbox_locked"):
                d["forensic_blackbox_payload"] = {
                    "locked": True,
                    "format": d.get("forensic_blackbox_payload", {}).get("format", ""),
                    "created_at": d.get("forensic_blackbox_payload", {}).get("created_at", ""),
                }
            if d.get("fl_model_update_shared"):
                fl = dict(d.get("fl_model_update_payload", {}))
                if "weights_delta" in fl and isinstance(fl["weights_delta"], dict):
                    fl["weights_delta"] = {k: round(float(v), 6) for k, v in fl["weights_delta"].items()}
                d["fl_model_update_payload"] = fl
            public_chain.append(d)
        return public_chain

    def get_did_document(self) -> Dict:
        return self.did_document

    def generate_did_proof(self, challenge: str) -> Dict:
        return self.did_identity.sign_challenge(challenge)

    @staticmethod
    def verify_did(challenge: str, proof: Dict, did_document: Dict) -> bool:
        return verify_did_proof(challenge, proof, did_document)


# ============================================================
# Test / Demo
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SmartCar Blockchain Python Core Test")
    print("=" * 60)

    bc = SmartCarBlockchain(
        vehicle_id=get_env("SMARTCAR_VEHICLE_ID", "SMARTCAR_VIN_2024_XYZ789"),
        password=get_env("SMARTCAR_PASSWORD", "SmartCarSecretKey2024!@#SecureXYZ"),
        auth_token=get_env("SMARTCAR_AUTH_TOKEN", "SECURE_AUTH_TOKEN_SHA3_2024"),
        chain_file=get_env("SMARTCAR_CHAIN_FILE_TEST", "logs/blockchain_test.json")
    )

    print("\n[1] Hash Algorithm Test")
    test = "SmartCar Security Test 2024"
    print(f"  Input  : {test}")
    print(f"  SHA2-256: {sha2_256(test)}")
    print(f"  SHA3-256: {sha3_256(test)}")
    print(f"  Dual Hash: {dual_hash(test)['combined']}")

    print("\n[2] Encryption Test")
    crypto = SmartCarCrypto("test_password")
    msg = "SECURE_AUTH_TOKEN_SHA3_2024"
    enc = crypto.encrypt(msg)
    dec = crypto.decrypt(enc)
    print(f"  Original : {msg}")
    print(f"  Encrypted: {enc[:40]}...")
    print(f"  Decrypted: {dec}")

    print("\n[3] Auth with wrong token")
    r = bc.authenticate("wrong_token")
    print(f"  Result: {r}")

    print("\n[4] Auth with correct token")
    r = bc.authenticate(get_env("SMARTCAR_AUTH_TOKEN", "SECURE_AUTH_TOKEN_SHA3_2024"))
    print(f"  Result: {r}")

    print("\n[5] Start engine")
    r = bc.start_engine()
    print(f"  Result: {r}")

    print("\n[6] Normal telemetry")
    tel = TelemetryData(speed=60.0, acceleration=2.0, fuel_level=85.0,
                        battery_voltage=12.4, engine_temp=87.0,
                        gps_lat=23.81, gps_lon=90.41,
                        obstacle_distance=500.0, rpm=3000, timestamp="")
    b = bc.push_telemetry(tel, "TELEMETRY:NORMAL")
    print(f"  Block {b.index}: {b.block_hash[:32]}...")

    print("\n[7] Emergency brake (obstacle at 45m)")
    tel2 = TelemetryData(speed=80.0, acceleration=-8.0, fuel_level=84.5,
                         obstacle_distance=45.0, emergency_brake_active=True,
                         brake_pressure=100.0, timestamp="")
    b2 = bc.push_telemetry(tel2)
    print(f"  Emergency triggered: {b2.emergency_brake_triggered}")

    print("\n[8] Chain verification")
    status = bc.verify_and_sync()
    print(f"  Valid: {status['valid']}, Blocks: {status['chain_length']}")

    print("\n[9] Full status")
    for k, v in bc.get_status().items():
        print(f"  {k}: {v}")

    print("\n[10] DID challenge proof")
    did_challenge = "SMARTCAR_DID_CHALLENGE_2026"
    did_proof = bc.generate_did_proof(did_challenge)
    did_ok = SmartCarBlockchain.verify_did(did_challenge, did_proof, bc.get_did_document())
    print(f"  DID: {bc.get_did_document().get('id')}")
    print(f"  DID verification: {'VALID' if did_ok else 'INVALID'}")

    bc.save()
    print("\n[DONE] Python blockchain core test complete.")

