# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
V2X protocol for SmartCar research demo.

Supports:
- V2V: Vehicle telemetry beacon exchange
- V2I: Infrastructure signal broadcast
"""

import json
import socket
import threading
import time
import hashlib
import hmac
import logging
import os
import sys
import base64
from datetime import datetime, timezone
from collections import deque
from typing import Callable, Dict, Optional, Deque, Any, List

try:
    from env_config import load_project_env_once, get_env, get_int
except Exception:
    from env_config import load_project_env_once, get_env, get_int

load_project_env_once()
logger = logging.getLogger("SmartCarV2X")

try:
    import oqs  # type: ignore
except Exception:
    oqs = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTOGRAPHY_AVAILABLE = True
except Exception:
    CRYPTOGRAPHY_AVAILABLE = False


def _now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _make_nonce(seed: str) -> str:
    """Generate short per-message nonce."""
    return hashlib.sha3_256(f"{seed}|{time.time()}".encode()).hexdigest()[:16]


class V2XMessageType:
    HELLO = "HELLO"
    HELLO_ACK = "HELLO_ACK"
    V2V_TELEMETRY = "V2V_TELEMETRY"
    V2I_SIGNAL = "V2I_SIGNAL"
    ALERT = "ALERT"
    PING = "PING"
    PONG = "PONG"
    CRYPTO_MODE_UPDATE = "CRYPTO_MODE_UPDATE"


def create_message(msg_type: str, sender_id: str, sender_type: str, payload: Dict,
                   security: Optional[Dict] = None) -> str:
    """Create one newline-delimited V2X JSON message."""
    msg = {
        "type": msg_type,
        "sender_id": sender_id,
        "sender_type": sender_type,
        "timestamp": _now(),
        "nonce": _make_nonce(sender_id + msg_type),
        "payload": payload,
    }
    if security:
        msg["security"] = dict(security)
    return json.dumps(msg, sort_keys=True) + "\n"


def parse_message(raw: str) -> Optional[Dict]:
    """Parse one V2X JSON line safely."""
    try:
        return json.loads(raw.strip())
    except Exception:
        return None


class DynamicCryptoAgilityLayer:
    """
    AI-like cryptographic agility:
    - chooses DILITHIUM when network budget allows
    - falls back to SHA3/HMAC under high latency/traffic to protect real-time decisions
    """

    MODE_SHA3 = "SHA3"
    MODE_DILITHIUM = "DILITHIUM"
    HS_NONE = "NONE"
    HS_PQC_KEM = "PQC_KEM"
    HS_ECDH = "ECDH"

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.shared_secret = get_env("SMARTCAR_V2X_SHARED_SECRET", "SMARTCAR_V2X_SHARED_SECRET_2026")
        self.mode = get_env("SMARTCAR_V2X_CRYPTO_DEFAULT", self.MODE_DILITHIUM).strip().upper()
        if self.mode not in (self.MODE_SHA3, self.MODE_DILITHIUM):
            self.mode = self.MODE_DILITHIUM
        self.force_mode = get_env("SMARTCAR_V2X_CRYPTO_FORCE_MODE", "").strip().upper()
        self.switch_interval_sec = float(get_env("SMARTCAR_V2X_CRYPTO_SWITCH_INTERVAL_SEC", "2.0"))
        self.latency_hi_ms = float(get_env("SMARTCAR_V2X_CRYPTO_LATENCY_HIGH_MS", "120.0"))
        self.traffic_hi_mps = float(get_env("SMARTCAR_V2X_CRYPTO_TRAFFIC_HIGH_MPS", "60.0"))
        self._metrics_window_sec = float(get_env("SMARTCAR_V2X_CRYPTO_METRICS_WINDOW_SEC", "4.0"))
        self._ewma_alpha = float(get_env("SMARTCAR_V2X_CRYPTO_EWMA_ALPHA", "0.28"))
        self._latency_weight = float(get_env("SMARTCAR_V2X_CRYPTO_WEIGHT_LATENCY", "0.65"))
        self._traffic_weight = float(get_env("SMARTCAR_V2X_CRYPTO_WEIGHT_TRAFFIC", "0.35"))
        total_w = self._latency_weight + self._traffic_weight
        if total_w <= 0.0:
            self._latency_weight, self._traffic_weight = 0.65, 0.35
            total_w = 1.0
        self._latency_weight /= total_w
        self._traffic_weight /= total_w
        self._score_up_threshold = float(get_env("SMARTCAR_V2X_CRYPTO_SCORE_UP_THRESHOLD", "0.72"))
        self._score_down_threshold = float(get_env("SMARTCAR_V2X_CRYPTO_SCORE_DOWN_THRESHOLD", "0.54"))
        if self._score_down_threshold > self._score_up_threshold:
            self._score_down_threshold, self._score_up_threshold = 0.54, 0.72
        self._rec_bias = float(get_env("SMARTCAR_V2X_CRYPTO_REC_BIAS", "0.08"))
        self._quantum_guard_max_score = float(get_env("SMARTCAR_V2X_CRYPTO_QUANTUM_GUARD_MAX_SCORE", "0.90"))
        self._switch_confirm_count = max(1, int(get_env("SMARTCAR_V2X_CRYPTO_SWITCH_CONFIRM_COUNT", "2")))
        self._last_switch_ts = 0.0
        self._rtt_ms_hist: Deque[float] = deque(maxlen=32)
        self._msg_ts_hist: Deque[float] = deque(maxlen=256)
        self._rtt_ewma_ms = 0.0
        self._pending_target = ""
        self._pending_target_count = 0
        self._last_agility_score = 0.0
        self._quantum_alert = get_env("SMARTCAR_V2X_QUANTUM_ALERT", "0") == "1"
        self._force_classic = get_env("SMARTCAR_V2X_FORCE_CLASSIC", "0") == "1"
        self._pqc_kem_preferred = get_env("SMARTCAR_V2X_PQC_KEM_PREFERRED", "Kyber512").strip() or "Kyber512"
        self._pqc_kem_candidates = [
            a.strip() for a in get_env("SMARTCAR_V2X_PQC_KEM_ALGS", "ML-KEM-512,Kyber512").split(",") if a.strip()
        ]
        self._pqc_kem_candidates = self._resolve_kem_candidates(self._pqc_kem_preferred, self._pqc_kem_candidates)
        self._pqc_sig_alg = get_env("SMARTCAR_V2X_PQC_SIG_ALG", "Dilithium2").strip() or "Dilithium2"
        self._session_id = "bootstrap"
        self._session_key = hashlib.sha3_256(self.shared_secret.encode()).digest()
        self._hs_mode = self.HS_NONE

        self._dilithium_pk_hex = ""
        self._dilithium_sk = None
        if oqs is not None and not self._force_classic:
            try:
                signer = oqs.Signature(self._pqc_sig_alg)
                self._dilithium_pk_hex = signer.generate_keypair().hex()
                self._dilithium_sk = signer.export_secret_key()
            except Exception:
                self._dilithium_pk_hex = ""
                self._dilithium_sk = None

        self._kem_alg = ""
        self._kem_pub_hex = ""
        self._kem_sk = None
        self._kem_enabled_mechanisms: List[str] = []
        self._kem_enabled_mechanisms_upper: set[str] = set()
        self._negotiated_kem_alg = ""
        self._prepare_kem_keypair()

        self._ecdsa_priv = None
        self._ecdsa_pub_hex = ""
        if CRYPTOGRAPHY_AVAILABLE:
            try:
                self._ecdsa_priv = ec.generate_private_key(ec.SECP256R1())
                pub = self._ecdsa_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )
                self._ecdsa_pub_hex = pub.hex()
            except Exception:
                self._ecdsa_priv = None
                self._ecdsa_pub_hex = ""

    def observe_latency(self, rtt_ms: float):
        rtt = max(0.0, float(rtt_ms))
        self._rtt_ms_hist.append(rtt)
        if self._rtt_ewma_ms <= 0.0:
            self._rtt_ewma_ms = rtt
        else:
            a = min(0.95, max(0.01, self._ewma_alpha))
            self._rtt_ewma_ms = (a * rtt) + ((1.0 - a) * self._rtt_ewma_ms)

    def observe_message(self):
        now = time.time()
        self._msg_ts_hist.append(now)
        cutoff = now - max(1.0, self._metrics_window_sec)
        while self._msg_ts_hist and self._msg_ts_hist[0] < cutoff:
            self._msg_ts_hist.popleft()

    def _agility_score(self, recommended_mode: str = "") -> float:
        avg_rtt = (sum(self._rtt_ms_hist) / len(self._rtt_ms_hist)) if self._rtt_ms_hist else 0.0
        effective_rtt = max(avg_rtt, self._rtt_ewma_ms)
        mps = len(self._msg_ts_hist) / max(1.0, self._metrics_window_sec)
        latency_component = min(1.0, effective_rtt / max(1.0, self.latency_hi_ms))
        traffic_component = min(1.0, mps / max(1.0, self.traffic_hi_mps))
        score = (self._latency_weight * latency_component) + (self._traffic_weight * traffic_component)

        rec = recommended_mode.strip().upper()
        if rec == self.MODE_SHA3:
            score = min(1.0, score + self._rec_bias)
        elif rec == self.MODE_DILITHIUM:
            score = max(0.0, score - self._rec_bias)
        self._last_agility_score = score
        return score

    def handshake_hello_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "pqc_sig_alg": self._pqc_sig_alg,
            "classic_sig_alg": "ECDSA_SECP256R1" if self._ecdsa_pub_hex else "NONE",
            "ecdh_pubkey": self._ecdsa_pub_hex,
            "preferred_kem_alg": self._pqc_kem_preferred,
            "kem_candidates": list(self._pqc_kem_candidates),
        }
        if self._kem_alg and self._kem_pub_hex:
            payload["kem_alg"] = self._kem_alg
            payload["kem_pubkey"] = self._kem_pub_hex
        return payload

    def accept_handshake_as_server(self, hello_payload: Dict[str, Any]) -> Dict[str, Any]:
        hs: Dict[str, Any] = {"hs_mode": self.HS_NONE}
        if not isinstance(hello_payload, dict):
            return hs
        if not self._force_classic and oqs is not None:
            try:
                peer_kem_alg = self._normalize_kem_alg(str(hello_payload.get("kem_alg", "")).strip())
                peer_kem_pub = str(hello_payload.get("kem_pubkey", "")).strip()
                if peer_kem_alg and peer_kem_pub and self._is_kem_supported(peer_kem_alg):
                    kem = oqs.KeyEncapsulation(peer_kem_alg)
                    ciphertext, shared = kem.encap_secret(bytes.fromhex(peer_kem_pub))
                    self._set_session_secret(shared, context=f"pqc_kem:{peer_kem_alg}")
                    hs = {
                        "hs_mode": self.HS_PQC_KEM,
                        "kem_alg": peer_kem_alg,
                        "kem_ciphertext": ciphertext.hex(),
                    }
                    return hs
            except Exception:
                pass
        if CRYPTOGRAPHY_AVAILABLE and self._ecdsa_priv:
            try:
                peer_ecdh_hex = str(hello_payload.get("ecdh_pubkey", "")).strip()
                if peer_ecdh_hex:
                    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(peer_ecdh_hex))
                    shared = self._ecdsa_priv.exchange(ec.ECDH(), peer_pub)
                    hk = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=self.shared_secret.encode(),
                        info=b"smartcar-v2x-ecdh",
                    )
                    self._set_session_secret(hk.derive(shared), context="ecdh")
                    hs = {
                        "hs_mode": self.HS_ECDH,
                        "ecdh_pubkey": self._ecdsa_pub_hex,
                    }
            except Exception:
                pass
        return hs

    def complete_handshake_as_client(self, ack_payload: Dict[str, Any]) -> bool:
        if not isinstance(ack_payload, dict):
            return False
        hs_mode = str(ack_payload.get("hs_mode", self.HS_NONE)).upper()
        if hs_mode == self.HS_PQC_KEM:
            try:
                kem_alg = self._normalize_kem_alg(str(ack_payload.get("kem_alg", "")).strip())
                kem_ct = str(ack_payload.get("kem_ciphertext", "")).strip()
                if (
                    oqs is None
                    or not self._kem_sk
                    or not kem_alg
                    or not kem_ct
                    or not self._is_kem_supported(kem_alg)
                ):
                    return False
                kem = oqs.KeyEncapsulation(kem_alg, secret_key=self._kem_sk)
                shared = kem.decap_secret(bytes.fromhex(kem_ct))
                self._set_session_secret(shared, context=f"pqc_kem:{kem_alg}")
                return True
            except Exception:
                return False
        if hs_mode == self.HS_ECDH:
            if not (CRYPTOGRAPHY_AVAILABLE and self._ecdsa_priv):
                return False
            try:
                peer_ecdh_hex = str(ack_payload.get("ecdh_pubkey", "")).strip()
                peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(peer_ecdh_hex))
                shared = self._ecdsa_priv.exchange(ec.ECDH(), peer_pub)
                hk = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.shared_secret.encode(),
                    info=b"smartcar-v2x-ecdh",
                )
                self._set_session_secret(hk.derive(shared), context="ecdh")
                return True
            except Exception:
                return False
        self._set_session_secret(hashlib.sha3_256(self.shared_secret.encode()).digest(), context="bootstrap")
        return True

    def maybe_switch_mode(self, recommended_mode: str = "") -> Optional[str]:
        now = time.time()
        if self.force_mode in (self.MODE_SHA3, self.MODE_DILITHIUM):
            if self.mode != self.force_mode:
                self.mode = self.force_mode
                self._last_switch_ts = now
                self._pending_target = ""
                self._pending_target_count = 0
                return self.mode
            return None
        score = self._agility_score(recommended_mode=recommended_mode)
        if self.mode == self.MODE_DILITHIUM:
            target = self.MODE_SHA3 if score >= self._score_up_threshold else self.MODE_DILITHIUM
        else:
            target = self.MODE_DILITHIUM if score <= self._score_down_threshold else self.MODE_SHA3

        if self._quantum_alert and score < self._quantum_guard_max_score:
            target = self.MODE_DILITHIUM

        if target == self.mode:
            self._pending_target = ""
            self._pending_target_count = 0
            return None

        if self._pending_target == target:
            self._pending_target_count += 1
        else:
            self._pending_target = target
            self._pending_target_count = 1

        if self._pending_target_count < self._switch_confirm_count:
            return None
        if now - self._last_switch_ts < self.switch_interval_sec:
            return None

        self.mode = target
        self._last_switch_ts = now
        self._pending_target = ""
        self._pending_target_count = 0
        return self.mode

    def sign_message(self, msg_without_security: Dict[str, Any]) -> Dict[str, Any]:
        canonical = json.dumps(msg_without_security, sort_keys=True, separators=(",", ":")).encode()
        sec = {
            "mode": self.mode,
            "ts": _now(),
            "hs_mode": self._hs_mode,
            "session_id": self._session_id,
        }
        if self.mode == self.MODE_DILITHIUM:
            sig = self._sign_dilithium(canonical)
            sec["signature"] = sig
            if sig and self._dilithium_pk_hex:
                sec["pubkey"] = self._dilithium_pk_hex
                sec["scheme"] = self._pqc_sig_alg.upper()
            else:
                ecdsa = self._sign_ecdsa(canonical)
                if ecdsa:
                    sec["signature"] = ecdsa
                    sec["pubkey"] = self._ecdsa_pub_hex
                    sec["scheme"] = "ECDSA-SECP256R1"
                else:
                    sec["signature"] = hmac.new(self._hmac_key(), canonical, hashlib.sha3_256).hexdigest()
                    sec["scheme"] = "HMAC-SHA3-256"
        else:
            sec["signature"] = hmac.new(self._hmac_key(), canonical, hashlib.sha3_256).hexdigest()
            sec["scheme"] = "HMAC-SHA3-256"
        return sec

    def verify_message(self, msg: Dict[str, Any]) -> bool:
        sec = msg.get("security", {})
        if not isinstance(sec, dict):
            return False
        mode = str(sec.get("mode", "")).upper()
        signature = str(sec.get("signature", ""))
        scheme = str(sec.get("scheme", "")).upper()
        if mode not in (self.MODE_SHA3, self.MODE_DILITHIUM) or not signature:
            return False
        bare = dict(msg)
        bare.pop("security", None)
        canonical = json.dumps(bare, sort_keys=True, separators=(",", ":")).encode()
        if mode == self.MODE_SHA3 or scheme == "HMAC-SHA3-256":
            expected = hmac.new(self._hmac_key(), canonical, hashlib.sha3_256).hexdigest()
            return hmac.compare_digest(signature, expected)
        if scheme == "ECDSA-SECP256R1":
            return self._verify_ecdsa(canonical, signature, str(sec.get("pubkey", "")))
        return self._verify_dilithium(canonical, signature, str(sec.get("pubkey", "")))

    def _sign_dilithium(self, payload: bytes) -> str:
        if oqs is not None and self._dilithium_sk and self._dilithium_pk_hex and not self._force_classic:
            try:
                signer = oqs.Signature(self._pqc_sig_alg, secret_key=self._dilithium_sk)
                return signer.sign(payload).hex()
            except Exception:
                return ""
        return ""

    def _verify_dilithium(self, payload: bytes, sig_hex: str, pub_hex: str) -> bool:
        if oqs is not None and pub_hex and not self._force_classic:
            try:
                verifier = oqs.Signature(self._pqc_sig_alg)
                return verifier.verify(payload, bytes.fromhex(sig_hex), bytes.fromhex(pub_hex))
            except Exception:
                pass
        return False

    def _sign_ecdsa(self, payload: bytes) -> str:
        if not (CRYPTOGRAPHY_AVAILABLE and self._ecdsa_priv):
            return ""
        try:
            sig = self._ecdsa_priv.sign(payload, ec.ECDSA(hashes.SHA256()))
            return base64.b64encode(sig).decode()
        except Exception:
            return ""

    def _verify_ecdsa(self, payload: bytes, sig_b64: str, pub_hex: str) -> bool:
        if not CRYPTOGRAPHY_AVAILABLE:
            return False
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pub_hex))
            pub.verify(base64.b64decode(sig_b64.encode()), payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def _hmac_key(self) -> bytes:
        return self._session_key if self._session_key else self.shared_secret.encode()

    def _set_session_secret(self, shared_secret: bytes, context: str):
        digest = hashlib.sha3_256(shared_secret + self.shared_secret.encode()).digest()
        self._session_key = digest
        self._session_id = hashlib.sha3_256((context + "|" + self.node_id).encode() + digest).hexdigest()[:16]
        if context.startswith("pqc_kem"):
            self._hs_mode = self.HS_PQC_KEM
            self._negotiated_kem_alg = context.split(":", 1)[1] if ":" in context else ""
        elif context == "ecdh":
            self._hs_mode = self.HS_ECDH
            self._negotiated_kem_alg = ""
        else:
            self._hs_mode = self.HS_NONE
            self._negotiated_kem_alg = ""

    def _prepare_kem_keypair(self):
        self._kem_alg = ""
        self._kem_pub_hex = ""
        self._kem_sk = None
        self._kem_enabled_mechanisms = []
        self._kem_enabled_mechanisms_upper = set()
        if oqs is None or self._force_classic:
            return
        self._kem_enabled_mechanisms = self._detect_enabled_kem_mechanisms()
        self._kem_enabled_mechanisms_upper = {a.upper() for a in self._kem_enabled_mechanisms}
        for alg in self._pqc_kem_candidates:
            if not self._is_kem_supported(alg):
                continue
            try:
                kem = oqs.KeyEncapsulation(alg)
                pub = kem.generate_keypair()
                sk = kem.export_secret_key()
                self._kem_alg = alg
                self._kem_pub_hex = pub.hex()
                self._kem_sk = sk
                return
            except Exception:
                continue

    def _detect_enabled_kem_mechanisms(self) -> List[str]:
        if oqs is None:
            return []
        probes = (
            "get_enabled_kem_mechanisms",
            "get_enabled_KEM_mechanisms",
            "get_supported_kem_mechanisms",
            "get_supported_KEM_mechanisms",
        )
        for fn_name in probes:
            fn = getattr(oqs, fn_name, None)
            if callable(fn):
                try:
                    values = fn()
                    if isinstance(values, (list, tuple)):
                        return [str(v) for v in values]
                except Exception:
                    continue
        return []

    def _resolve_kem_candidates(self, preferred: str, configured: List[str]) -> List[str]:
        uniq: List[str] = []
        seen = set()
        for raw in [preferred] + list(configured):
            alg = self._normalize_kem_alg(raw)
            if not alg:
                continue
            up = alg.upper()
            if up in seen:
                continue
            seen.add(up)
            uniq.append(alg)
        return uniq or ["Kyber512", "ML-KEM-512"]

    def _normalize_kem_alg(self, alg: str) -> str:
        raw = str(alg or "").strip()
        if not raw:
            return ""
        aliases = {
            "KYBER": "Kyber512",
            "KYBER512": "Kyber512",
            "KYBER768": "Kyber768",
            "KYBER1024": "Kyber1024",
            "MLKEM512": "ML-KEM-512",
            "ML-KEM512": "ML-KEM-512",
            "ML-KEM-512": "ML-KEM-512",
            "MLKEM768": "ML-KEM-768",
            "ML-KEM768": "ML-KEM-768",
            "ML-KEM-768": "ML-KEM-768",
            "MLKEM1024": "ML-KEM-1024",
            "ML-KEM1024": "ML-KEM-1024",
            "ML-KEM-1024": "ML-KEM-1024",
        }
        up = raw.upper().replace("_", "-")
        return aliases.get(up, raw)

    def _is_kem_supported(self, alg: str) -> bool:
        if oqs is None:
            return False
        cand = self._normalize_kem_alg(alg)
        if not cand:
            return False
        if self._kem_enabled_mechanisms_upper and cand.upper() not in self._kem_enabled_mechanisms_upper:
            return False
        return True


class V2XHub:
    def __init__(self, host: str = None, port: int = None):
        """Initialize V2X hub socket state."""
        self.host = host or get_env("SMARTCAR_V2X_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_V2X_PORT", 9988)
        self._running = False
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._clients: Dict[socket.socket, Dict] = {}
        self._msg_ts_hist: Deque[float] = deque(maxlen=1024)
        self._latency_hint_ms = float(get_env("SMARTCAR_V2X_HUB_LATENCY_HINT_MS", "20.0"))

    def start(self):
        """Start V2X hub server and accept loop."""
        if self._running:
            return
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.host, self.port))
            self._sock.listen(32)
            self._sock.settimeout(1.0)
        except OSError:
            self._running = False
            try:
                self._sock.close()
            except Exception as e:
                logger.debug("V2X hub socket close after bind failure: %s", e)
            raise
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        """Stop hub and close connected sockets."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception as e:
                logger.debug("V2X hub main socket close error: %s", e)
        with self._lock:
            sockets = list(self._clients.keys())
            self._clients.clear()
        for s in sockets:
            try:
                s.close()
            except Exception as e:
                logger.debug("V2X hub client socket close error: %s", e)

    def _accept_loop(self):
        """Accept clients and start per-client loops."""
        while self._running:
            try:
                conn, _addr = self._sock.accept()
                conn.settimeout(1.0)
                with self._lock:
                    self._clients[conn] = {
                        "node_id": "unknown",
                        "node_type": "unknown",
                        "crypto_mode": DynamicCryptoAgilityLayer.MODE_DILITHIUM,
                        "crypto": DynamicCryptoAgilityLayer(node_id=f"v2x_hub_peer_{id(conn)}"),
                    }
                threading.Thread(target=self._client_loop, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.warning("V2X accept loop socket error", exc_info=True)
                    continue
                break
            except Exception:
                if self._running:
                    logger.exception("V2X accept loop unexpected error")
                    continue

    def _client_loop(self, conn: socket.socket):
        """Receive and route messages from one client."""
        buf = ""
        try:
            while self._running:
                try:
                    chunk = conn.recv(4096).decode(errors="replace")
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if not line.strip():
                        continue
                    msg = parse_message(line)
                    if not msg:
                        continue
                    self._msg_ts_hist.append(time.time())
                    self._handle_msg(conn, msg)
        finally:
            with self._lock:
                self._clients.pop(conn, None)
            try:
                conn.close()
            except Exception as e:
                logger.debug("V2X client socket close error: %s", e)

    def _handle_msg(self, conn: socket.socket, msg: Dict):
        """Handle HELLO/PING locally or broadcast payload."""
        mtype = msg.get("type", "")
        sender_id = msg.get("sender_id", "unknown")
        sender_type = msg.get("sender_type", "unknown")
        if mtype == V2XMessageType.HELLO:
            hello_payload = msg.get("payload", {})
            hs_ack: Dict[str, Any] = {"hs_mode": DynamicCryptoAgilityLayer.HS_NONE}
            with self._lock:
                if conn in self._clients:
                    self._clients[conn]["node_id"] = sender_id
                    self._clients[conn]["node_type"] = sender_type
                    self._clients[conn]["crypto_mode"] = str(hello_payload.get("selected_crypto_mode", ""))
                    peer_crypto = self._clients[conn].get("crypto")
                    if isinstance(peer_crypto, DynamicCryptoAgilityLayer):
                        hs_ack = peer_crypto.accept_handshake_as_server(hello_payload)
            ack = create_message(
                V2XMessageType.HELLO_ACK,
                sender_id="v2x_hub",
                sender_type="infrastructure",
                payload={
                    "status": "CONNECTED",
                    "hub_time": _now(),
                    "recommended_crypto_mode": self._recommend_crypto_mode(),
                    "handshake": hs_ack,
                },
            )
            try:
                conn.sendall(ack.encode())
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                logger.warning("Failed to send HELLO_ACK to %s", sender_id, exc_info=True)
                pass
            return
        if mtype == V2XMessageType.PING:
            pong = create_message(
                V2XMessageType.PONG,
                sender_id="v2x_hub",
                sender_type="infrastructure",
                payload={"ok": True},
            )
            try:
                conn.sendall(pong.encode())
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                logger.warning("Failed to send PONG to %s", sender_id, exc_info=True)
                pass
            return

        # Validate cryptographic envelope for data-plane messages.
        if mtype not in (V2XMessageType.PING, V2XMessageType.PONG, V2XMessageType.HELLO, V2XMessageType.HELLO_ACK):
            peer_crypto = None
            with self._lock:
                if conn in self._clients:
                    peer_crypto = self._clients[conn].get("crypto")
            verifier = peer_crypto if isinstance(peer_crypto, DynamicCryptoAgilityLayer) else None
            if verifier is None or not verifier.verify_message(msg):
                logger.warning("Dropping message with invalid crypto envelope from %s", sender_id)
                return

        self._broadcast(msg, exclude=conn)

    def _recommend_crypto_mode(self) -> str:
        now = time.time()
        cutoff = now - 4.0
        while self._msg_ts_hist and self._msg_ts_hist[0] < cutoff:
            self._msg_ts_hist.popleft()
        mps = len(self._msg_ts_hist) / 4.0
        with self._lock:
            client_load = len(self._clients)
        score = (
            0.5 * min(1.0, mps / float(max(1, get_int("SMARTCAR_V2X_CRYPTO_TRAFFIC_HIGH_MPS", 60)))) +
            0.3 * min(1.0, client_load / 24.0) +
            0.2 * min(1.0, self._latency_hint_ms / float(max(1, get_int("SMARTCAR_V2X_CRYPTO_LATENCY_HIGH_MS", 120))))
        )
        return DynamicCryptoAgilityLayer.MODE_SHA3 if score >= 0.66 else DynamicCryptoAgilityLayer.MODE_DILITHIUM

    def _broadcast(self, msg: Dict, exclude: Optional[socket.socket] = None):
        """Broadcast message to all connected nodes except sender."""
        payload = (json.dumps(msg, sort_keys=True) + "\n").encode()
        with self._lock:
            targets = list(self._clients.keys())
        for s in targets:
            if exclude is not None and s == exclude:
                continue
            try:
                s.sendall(payload)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                with self._lock:
                    self._clients.pop(s, None)
                try:
                    s.close()
                except Exception as e:
                    logger.debug("V2X broadcast target close error: %s", e)


class V2XNode:
    def __init__(
        self,
        node_id: str,
        node_type: str,
        host: str = None,
        port: int = None,
        on_message: Optional[Callable[[Dict], None]] = None,
    ):
        """Initialize V2X node client with callback hook."""
        self.node_id = node_id
        self.node_type = node_type
        self.host = host or get_env("SMARTCAR_V2X_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_V2X_PORT", 9988)
        self.on_message = on_message
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._lock = threading.Lock()
        self._recv_thread: Optional[threading.Thread] = None
        self.crypto_layer = DynamicCryptoAgilityLayer(node_id=self.node_id)

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self, timeout: float = 3.0) -> bool:
        """Connect node to hub and complete HELLO handshake."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(timeout)
            self._sock.connect((self.host, self.port))
            self._sock.settimeout(1.0)
            t0 = time.perf_counter()
            hello = create_message(
                V2XMessageType.HELLO,
                sender_id=self.node_id,
                sender_type=self.node_type,
                payload={
                    "node_version": "1.0",
                    "crypto_capabilities": ["SHA3", "DILITHIUM", "ECDSA", "ECDH", "PQC_KEM"],
                    "selected_crypto_mode": self.crypto_layer.mode,
                    **self.crypto_layer.handshake_hello_payload(),
                },
            )
            self._sock.sendall(hello.encode())
            raw = self._recv_line()
            msg = parse_message(raw) if raw else None
            if not msg or msg.get("type") != V2XMessageType.HELLO_ACK:
                self.disconnect()
                return False
            rtt_ms = (time.perf_counter() - t0) * 1000.0
            self.crypto_layer.observe_latency(rtt_ms)
            payload = msg.get("payload", {}) if isinstance(msg.get("payload", {}), dict) else {}
            hs_ok = self.crypto_layer.complete_handshake_as_client(payload.get("handshake", {}))
            if not hs_ok:
                # Keep data-plane authenticated with asymmetric signatures if session KEX fails.
                self.crypto_layer.force_mode = DynamicCryptoAgilityLayer.MODE_DILITHIUM
            rec_mode = str(payload.get("recommended_crypto_mode", ""))
            self.crypto_layer.maybe_switch_mode(recommended_mode=rec_mode)
            self._connected = True
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._recv_thread.start()
            return True
        except Exception:
            logger.exception("V2X node connect failed (%s:%s)", self.host, self.port)
            self.disconnect()
            return False

    def disconnect(self):
        """Disconnect node socket."""
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except Exception as e:
                logger.debug("V2X node socket close error: %s", e)
            self._sock = None

    def _recv_line(self) -> Optional[str]:
        """Read one newline-delimited message."""
        if not self._sock:
            return None
        buf = ""
        while "\n" not in buf:
            try:
                chunk = self._sock.recv(4096).decode(errors="replace")
            except socket.timeout:
                continue
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf.split("\n", 1)[0]

    def _recv_loop(self):
        """Receive loop for async messages from hub."""
        if not self._sock:
            return
        buf = ""
        while self._connected:
            try:
                chunk = self._sock.recv(4096).decode(errors="replace")
            except socket.timeout:
                continue
            except Exception:
                self._connected = False
                break
            if not chunk:
                self._connected = False
                break
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if not line.strip():
                    continue
                msg = parse_message(line)
                if msg and self.on_message:
                    self.crypto_layer.observe_message()
                    rec_mode = str(msg.get("payload", {}).get("recommended_crypto_mode", ""))
                    self.crypto_layer.maybe_switch_mode(recommended_mode=rec_mode)
                    try:
                        self.on_message(msg)
                    except Exception:
                        logger.exception("V2X on_message callback error")
                        continue

    def send(self, msg_type: str, payload: Dict) -> bool:
        """Send one message to hub."""
        if not self._connected or not self._sock:
            return False
        switched = self.crypto_layer.maybe_switch_mode()
        if switched:
            logger.info("V2X crypto mode switched to %s for %s", switched, self.node_id)
        base = {
            "type": msg_type,
            "sender_id": self.node_id,
            "sender_type": self.node_type,
            "timestamp": _now(),
            "nonce": _make_nonce(self.node_id + msg_type),
            "payload": payload,
        }
        security = self.crypto_layer.sign_message(base)
        base["security"] = security
        data = (json.dumps(base, sort_keys=True) + "\n").encode()
        with self._lock:
            try:
                self._sock.sendall(data)
                self.crypto_layer.observe_message()
                return True
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                self._connected = False
                return False

    def send_v2v_telemetry(self, speed: float, lat: float, lon: float, heading: float = 0.0) -> bool:
        """Send compact V2V telemetry beacon."""
        return self.send(V2XMessageType.V2V_TELEMETRY, {
            "speed": round(float(speed), 2),
            "lat": round(float(lat), 6),
            "lon": round(float(lon), 6),
            "heading": round(float(heading), 2),
        })

    def send_v2i_signal(self, intersection_id: str, signal_state: str, ttl_sec: int = 10,
                        extra_payload: Optional[Dict] = None) -> bool:
        """Send V2I infrastructure command payload."""
        payload = {
            "intersection_id": intersection_id,
            "signal_state": signal_state,
            "ttl_sec": int(ttl_sec),
        }
        if extra_payload:
            payload.update(extra_payload)
        return self.send(V2XMessageType.V2I_SIGNAL, payload)


if __name__ == "__main__":
    print("Starting V2X hub on 127.0.0.1:9988")
    hub = V2XHub()
    hub.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        hub.stop()
        print("V2X hub stopped.")

