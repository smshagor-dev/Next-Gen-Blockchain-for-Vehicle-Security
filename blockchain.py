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
import struct
import base64
import secrets
import hmac
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict
from pathlib import Path
import threading
import logging

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
        verify_speed_limit_proof,
        create_location_ownership_proof,
        verify_location_ownership_proof,
    )
except Exception:
    from zkp_privacy import (
        create_speed_limit_proof,
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
    timestamp: str = ""

    def to_string(self) -> str:
        return (f"{self.speed},{self.acceleration},{self.fuel_level},"
                f"{self.battery_voltage},{self.engine_temp},"
                f"{self.gps_lat},{self.gps_lon},{self.obstacle_distance},"
                f"{self.emergency_brake_active},{self.steering_angle},"
                f"{self.brake_pressure},{self.throttle_position},"
                f"{self.rpm},{self.odometer},{self.timestamp}")

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
        self.consensus = CONSENSUS_POA

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
        self.edge_enabled = get_env("SMARTCAR_EDGE_ENABLED", "1") == "1"
        self.edge_window_size = get_int("SMARTCAR_EDGE_WINDOW_SIZE", 5)
        self.edge_flush_interval_sec = float(get_env("SMARTCAR_EDGE_FLUSH_INTERVAL_SEC", "2.0"))
        self.edge_layer = EdgeTelemetryLayer(
            enabled=self.edge_enabled,
            window_size=self.edge_window_size,
            flush_interval_sec=self.edge_flush_interval_sec
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
        if get_env("SMARTCAR_OWNER_RECOVERY_KEY", "").strip() == "":
            logger.warning(
                "SMARTCAR_OWNER_RECOVERY_KEY à¦¨à¦¾ à¦¥à¦¾à¦•à¦¾à§Ÿ auth token fallback recovery key à¦¹à¦¿à¦¸à§‡à¦¬à§‡ à¦¬à§à¦¯à¦¬à¦¹à§ƒà¦¤ à¦¹à¦šà§à¦›à§‡. "
                "Production à¦ à¦†à¦²à¦¾à¦¦à¦¾ à¦¶à¦•à§à¦¤à¦¿à¦¶à¦¾à¦²à§€ recovery key à¦¸à§‡à¦Ÿ à¦•à¦°à§à¦¨."
            )

        # Vehicle state
        self.car_unlocked = False
        self.engine_started = False
        self.emergency_brake_active = False
        self.failed_auth_attempts = 0
        self.MAX_FAILED_AUTHS = 3
        self.locked_out = False

        # Create genesis
        self._create_genesis()
        logger.info(
            f"SmartCar Blockchain initialized for vehicle: {vehicle_id} | "
            f"consensus={self.consensus} | validator={self.validator_id} | "
            f"edge_enabled={self.edge_enabled} | storage_encryption={self.storage_encryption_enabled}"
        )

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

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
            block.privacy_preserving = True
            block.edge_processed = bool(edge_meta)
            block.edge_summary = dict(edge_meta or {})
            # Check emergency brake
            if (telemetry.obstacle_distance < EMERGENCY_BRAKE_DISTANCE
                    and self.engine_started):
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

            block.compute_hashes(self.crypto, self.validator_key)
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
                },
                block_hash=block.block_hash
            )
            self.chain.append(block)
            return block

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
        self._add_block(TelemetryData(timestamp=self._now()), "ENGINE:STOPPED")
        return {'success': True}

    def lock_car(self):
        self.flush_edge_to_chain("EDGE:FLUSH:LOCK")
        self.car_unlocked = False
        self.engine_started = False
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
        self.failed_auth_attempts = 0
        self.car_unlocked = True
        self.engine_started = False
        self.emergency_brake_active = False
        self._add_block(TelemetryData(timestamp=self._now()), "RECOVERY:OWNER_UNLOCK:CHAIN_RESET")
        logger.critical("Owner recovery unlock completed with chain reset")
        return {'success': True, 'mode': 'OWNER_RESET_UNLOCK', 'chain_reset': True}

    def push_telemetry(self, telemetry: TelemetryData, event: str = "") -> Block:
        event = event or "TELEMETRY:UPDATE"
        raw = asdict(telemetry)

        urgent = (
            "EMERGENCY" in event.upper()
            or "AUTH:" in event.upper()
            or "ENGINE:" in event.upper()
            or "V2X:" in event.upper()
            or "V2V:" in event.upper()
            or "V2I:" in event.upper()
        )

        if not self.edge_enabled or urgent:
            return self._add_block(telemetry, event, edge_meta={"bypass": True, "reason": "urgent" if urgent else "disabled"})

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
            timestamp=s["timestamp"],
        )
        return self._add_block(summary_tel, summary["event"], edge_meta=summary.get("meta", {}))

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
            timestamp=s["timestamp"],
        )
        self._add_block(summary_tel, flushed["event"], edge_meta=flushed.get("meta", {}))

    # ---- Verification ----

    def verify_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i-1]
            expected_validator = self._expected_validator(curr.index)
            if curr.consensus != self.consensus:
                logger.error(f"Block {i} consensus mismatch")
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
                'flush_interval_sec': self.edge_flush_interval_sec
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
            'privacy_preserving': True,
            'speed_limit_kmh': self.speed_limit_kmh,
            'anomaly_detection_enabled': True,
            'smart_contracts_enabled': self.smart_contract_engine.enabled,
            'edge_enabled': self.edge_enabled,
            'edge_window_size': self.edge_window_size,
            'chain_length': len(self.chain),
            'car_unlocked': self.car_unlocked,
            'engine_started': self.engine_started,
            'emergency_brake_active': self.emergency_brake_active,
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
        }

    def get_chain_json(self) -> List[Dict]:
        return [b.to_dict() for b in self.chain]

    def get_public_chain_json(self) -> List[Dict]:
        public_chain = []
        for b in self.chain:
            d = b.to_dict()
            if "telemetry" in d:
                d["telemetry"]["speed"] = None
                d["telemetry"]["gps_lat"] = None
                d["telemetry"]["gps_lon"] = None
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

