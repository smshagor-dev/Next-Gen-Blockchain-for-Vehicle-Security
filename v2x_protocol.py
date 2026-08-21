"""OmniGuard V2X secure vehicle-to-everything transport.

Phase-1 hardening establishes an authenticated trust boundary between each V2X
node and the hub. The hub authenticates node identity before accepting a
session, validates every data-plane message, and re-authenticates forwarded
messages separately for each recipient.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional

from env_config import get_bool, get_env, get_int, get_required_secret, load_project_env_once
from security_capabilities import ECDH_P256_WARNING, security_capability_output

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
    hashes = serialization = ec = HKDF = None
    CRYPTOGRAPHY_AVAILABLE = False

MAX_MESSAGE_BYTES = 1_048_576
DEFAULT_REPLAY_WINDOW_SEC = 15
_NODE_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
_WEAK_SECRETS = {
    "smartcar_v2x_shared_secret_2026",
    "smartcar_v2x_shared_secret_2026_change_me",
    "change-me",
    "changeme",
    "password",
    "secret",
    "default",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_nonce(_seed: str = "") -> str:
    """Return a cryptographically random 128-bit nonce.

    The optional seed is retained for API compatibility and intentionally does
    not influence entropy.
    """
    return secrets.token_hex(16)


def _canonical_json(value: Dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _parse_timestamp(value: Any) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _fresh_timestamp(value: Any, max_skew_sec: int) -> bool:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return False
    skew = abs((datetime.now(timezone.utc) - parsed).total_seconds())
    return skew <= max(1, int(max_skew_sec))


def _prune_replay_cache(cache: Dict[str, float], now: float) -> None:
    for nonce in [key for key, expiry in cache.items() if expiry <= now]:
        cache.pop(nonce, None)


def _claim_nonce(cache: Optional[Dict[str, float]], nonce: str, window_sec: int) -> bool:
    if cache is None:
        return True
    if len(nonce) < 16:
        return False
    now = time.monotonic()
    _prune_replay_cache(cache, now)
    if nonce in cache:
        return False
    cache[nonce] = now + max(1, int(window_sec))
    return True


def _validate_secret(value: str, name: str, min_length: int = 32) -> str:
    secret = str(value or "").strip()
    if len(secret) < min_length:
        raise RuntimeError(f"{name} must contain at least {min_length} characters")
    lowered = secret.lower()
    if lowered in _WEAK_SECRETS or "change_me" in lowered or "changeme" in lowered:
        raise RuntimeError(f"{name} contains an insecure placeholder/default value")
    return secret


def _load_secret_registry(env_name: str) -> Dict[str, str]:
    raw = get_env(env_name, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"{env_name} must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{env_name} must be a JSON object")
    result: Dict[str, str] = {}
    for raw_id, raw_secret in parsed.items():
        node_id = str(raw_id).strip()
        if not _NODE_ID_RE.fullmatch(node_id):
            raise RuntimeError(f"{env_name} contains an invalid node identity")
        result[node_id] = _validate_secret(str(raw_secret), f"{env_name}[{node_id}]")
    return result


def _new_message(msg_type: str, sender_id: str, sender_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": str(msg_type),
        "sender_id": str(sender_id),
        "sender_type": str(sender_type),
        "timestamp": _now(),
        "nonce": _make_nonce(),
        "payload": dict(payload),
    }


def _auth_mac(secret: str, message: Dict[str, Any], field: str) -> str:
    bare = dict(message)
    bare.pop(field, None)
    return hmac.new(secret.encode(), _canonical_json(bare).encode(), hashlib.sha256).hexdigest()


class V2XMessageType:
    HELLO = "HELLO"
    HELLO_ACK = "HELLO_ACK"
    V2V_TELEMETRY = "V2V_TELEMETRY"
    V2I_SIGNAL = "V2I_SIGNAL"
    ALERT = "ALERT"
    PING = "PING"
    PONG = "PONG"
    CRYPTO_MODE_UPDATE = "CRYPTO_MODE_UPDATE"


def create_message(
    msg_type: str,
    sender_id: str,
    sender_type: str,
    payload: Dict,
    security: Optional[Dict] = None,
) -> str:
    """Create one newline-delimited V2X JSON message.

    This helper does not authenticate a HELLO by itself. V2XNode and V2XHub
    add the appropriate handshake/data-plane authentication envelopes.
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")
    msg = _new_message(msg_type, sender_id, sender_type, payload)
    if security:
        msg["security"] = dict(security)
    return _canonical_json(msg) + "\n"


def parse_message(raw: str) -> Optional[Dict]:
    try:
        if not isinstance(raw, str) or not raw.strip():
            return None
        if len(raw.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
            return None
        parsed = json.loads(raw.strip())
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


class DynamicCryptoAgilityLayer:
    """Per-peer cryptographic session with identity/key pinning and replay checks."""

    MODE_SHA3 = "SHA3"
    MODE_DILITHIUM = "DILITHIUM"

    HS_NONE = "NONE"
    HS_PSK = "PSK"
    HS_PQC_KEM = "PQC_KEM"
    HS_ECDH = "ECDH"

    def __init__(self, node_id: str, shared_secret: Optional[str] = None):
        self.node_id = str(node_id)
        if shared_secret is None:
            shared_secret = get_required_secret("SMARTCAR_V2X_SHARED_SECRET", min_length=32)
        self.shared_secret = _validate_secret(shared_secret, "SMARTCAR_V2X_SHARED_SECRET")

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
        total_weight = self._latency_weight + self._traffic_weight
        if total_weight <= 0:
            self._latency_weight, self._traffic_weight, total_weight = 0.65, 0.35, 1.0
        self._latency_weight /= total_weight
        self._traffic_weight /= total_weight
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
        self._quantum_alert = get_bool("SMARTCAR_V2X_QUANTUM_ALERT", False)
        self._force_classic = get_bool("SMARTCAR_V2X_FORCE_CLASSIC", False)
        self._allow_ecdh_fallback = get_bool("SMARTCAR_V2X_ALLOW_CLASSICAL_ECDH_FALLBACK", False)
        if self._allow_ecdh_fallback:
            logger.warning(ECDH_P256_WARNING)

        self._pqc_kem_preferred = get_env("SMARTCAR_V2X_PQC_KEM_PREFERRED", "ML-KEM-512").strip() or "ML-KEM-512"
        self._pqc_kem_candidates = [
            item.strip()
            for item in get_env("SMARTCAR_V2X_PQC_KEM_ALGS", "ML-KEM-512,Kyber512").split(",")
            if item.strip()
        ]
        self._pqc_kem_candidates = self._resolve_kem_candidates(
            self._pqc_kem_preferred, self._pqc_kem_candidates
        )
        self._pqc_sig_alg = get_env("SMARTCAR_V2X_PQC_SIG_ALG", "Dilithium2").strip() or "Dilithium2"

        self._session_key = b""
        self._session_id = ""
        self._hs_mode = self.HS_NONE
        self._negotiated_kem_alg = ""
        self._peer_sig_scheme = ""
        self._peer_sig_pubkey = ""

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
        self._prepare_kem_keypair()

        self._ecdsa_priv = None
        self._ecdsa_pub_hex = ""
        if CRYPTOGRAPHY_AVAILABLE and self._allow_ecdh_fallback:
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

    @property
    def session_established(self) -> bool:
        return bool(self._session_key and self._session_id and self._hs_mode != self.HS_NONE)

    def observe_latency(self, rtt_ms: float):
        rtt = max(0.0, float(rtt_ms))
        self._rtt_ms_hist.append(rtt)
        if self._rtt_ewma_ms <= 0.0:
            self._rtt_ewma_ms = rtt
        else:
            alpha = min(0.95, max(0.01, self._ewma_alpha))
            self._rtt_ewma_ms = alpha * rtt + (1.0 - alpha) * self._rtt_ewma_ms

    def observe_message(self):
        now = time.time()
        self._msg_ts_hist.append(now)
        cutoff = now - max(1.0, self._metrics_window_sec)
        while self._msg_ts_hist and self._msg_ts_hist[0] < cutoff:
            self._msg_ts_hist.popleft()

    def _agility_score(self, recommended_mode: str = "") -> float:
        avg_rtt = sum(self._rtt_ms_hist) / len(self._rtt_ms_hist) if self._rtt_ms_hist else 0.0
        effective_rtt = max(avg_rtt, self._rtt_ewma_ms)
        mps = len(self._msg_ts_hist) / max(1.0, self._metrics_window_sec)
        latency_component = min(1.0, effective_rtt / max(1.0, self.latency_hi_ms))
        traffic_component = min(1.0, mps / max(1.0, self.traffic_hi_mps))
        score = self._latency_weight * latency_component + self._traffic_weight * traffic_component
        rec = str(recommended_mode).strip().upper()
        if rec == self.MODE_SHA3:
            score = min(1.0, score + self._rec_bias)
        elif rec == self.MODE_DILITHIUM:
            score = max(0.0, score - self._rec_bias)
        self._last_agility_score = score
        return score

    def _local_signature_identity(self) -> tuple[str, str]:
        if self._dilithium_pk_hex and self._dilithium_sk and not self._force_classic:
            return self._pqc_sig_alg.upper(), self._dilithium_pk_hex
        if self._ecdsa_pub_hex and self._ecdsa_priv and self._allow_ecdh_fallback:
            return "ECDSA-SECP256R1", self._ecdsa_pub_hex
        return "HMAC-SHA3-256", ""

    def handshake_hello_payload(self) -> Dict[str, Any]:
        sig_scheme, sig_pubkey = self._local_signature_identity()
        payload: Dict[str, Any] = {
            "pqc_sig_alg": self._pqc_sig_alg,
            "sig_scheme": sig_scheme,
            "sig_pubkey": sig_pubkey,
            "classic_sig_alg": "ECDSA_SECP256R1" if self._allow_ecdh_fallback and self._ecdsa_pub_hex else "NONE",
            "ecdh_fallback": "enabled_classical" if self._allow_ecdh_fallback else "disabled_by_default",
            "preferred_kem_alg": self._pqc_kem_preferred,
            "kem_candidates": list(self._pqc_kem_candidates),
            "security_capabilities": security_capability_output(self._allow_ecdh_fallback),
        }
        if self._allow_ecdh_fallback and self._ecdsa_pub_hex:
            payload["ecdh_pubkey"] = self._ecdsa_pub_hex
        if self._kem_alg and self._kem_pub_hex:
            payload["kem_alg"] = self._kem_alg
            payload["kem_pubkey"] = self._kem_pub_hex
        return payload

    def pin_peer_identity(self, hello_payload: Dict[str, Any]) -> bool:
        if not isinstance(hello_payload, dict):
            return False
        scheme = str(hello_payload.get("sig_scheme", "")).upper().strip()
        pubkey = str(hello_payload.get("sig_pubkey", "")).strip()
        if scheme == "HMAC-SHA3-256":
            self._peer_sig_scheme = scheme
            self._peer_sig_pubkey = ""
            return True
        if scheme == "ECDSA-SECP256R1" and pubkey:
            self._peer_sig_scheme = scheme
            self._peer_sig_pubkey = pubkey
            return True
        if scheme and pubkey and ("DILITHIUM" in scheme or "ML-DSA" in scheme):
            self._peer_sig_scheme = scheme
            self._peer_sig_pubkey = pubkey
            return True
        return False

    def accept_handshake_as_server(
        self, hello_payload: Dict[str, Any], session_context: str = ""
    ) -> Dict[str, Any]:
        if not isinstance(hello_payload, dict) or not session_context:
            return {"hs_mode": self.HS_NONE}

        if not self._force_classic and oqs is not None:
            try:
                peer_alg = self._normalize_kem_alg(str(hello_payload.get("kem_alg", "")).strip())
                peer_pub = str(hello_payload.get("kem_pubkey", "")).strip()
                if peer_alg and peer_pub and self._is_kem_supported(peer_alg):
                    kem = oqs.KeyEncapsulation(peer_alg)
                    ciphertext, shared = kem.encap_secret(bytes.fromhex(peer_pub))
                    self._set_session_secret(shared, f"pqc_kem:{peer_alg}", session_context)
                    return {
                        "hs_mode": self.HS_PQC_KEM,
                        "kem_alg": peer_alg,
                        "kem_ciphertext": ciphertext.hex(),
                    }
            except Exception:
                logger.debug("PQC KEM negotiation failed", exc_info=True)

        if self._allow_ecdh_fallback and CRYPTOGRAPHY_AVAILABLE and self._ecdsa_priv:
            try:
                peer_hex = str(hello_payload.get("ecdh_pubkey", "")).strip()
                if peer_hex:
                    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                        ec.SECP256R1(), bytes.fromhex(peer_hex)
                    )
                    shared = self._ecdsa_priv.exchange(ec.ECDH(), peer_pub)
                    hk = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=self.shared_secret.encode(),
                        info=b"omniguard-v2x-ecdh",
                    )
                    self._set_session_secret(hk.derive(shared), "ecdh", session_context)
                    return {"hs_mode": self.HS_ECDH, "ecdh_pubkey": self._ecdsa_pub_hex}
            except Exception:
                logger.debug("ECDH fallback negotiation failed", exc_info=True)

        self._set_psk_session(session_context)
        return {"hs_mode": self.HS_PSK}

    def complete_handshake_as_client(
        self, ack_payload: Dict[str, Any], session_context: str = ""
    ) -> bool:
        if not isinstance(ack_payload, dict) or not session_context:
            return False
        hs_mode = str(ack_payload.get("hs_mode", self.HS_NONE)).upper()

        if hs_mode == self.HS_PQC_KEM:
            try:
                kem_alg = self._normalize_kem_alg(str(ack_payload.get("kem_alg", "")).strip())
                kem_ct = str(ack_payload.get("kem_ciphertext", "")).strip()
                if oqs is None or not self._kem_sk or not kem_alg or not kem_ct or not self._is_kem_supported(kem_alg):
                    return False
                kem = oqs.KeyEncapsulation(kem_alg, secret_key=self._kem_sk)
                shared = kem.decap_secret(bytes.fromhex(kem_ct))
                self._set_session_secret(shared, f"pqc_kem:{kem_alg}", session_context)
                return True
            except Exception:
                return False

        if hs_mode == self.HS_ECDH:
            if not (self._allow_ecdh_fallback and CRYPTOGRAPHY_AVAILABLE and self._ecdsa_priv):
                return False
            try:
                peer_hex = str(ack_payload.get("ecdh_pubkey", "")).strip()
                peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), bytes.fromhex(peer_hex)
                )
                shared = self._ecdsa_priv.exchange(ec.ECDH(), peer_pub)
                hk = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.shared_secret.encode(),
                    info=b"omniguard-v2x-ecdh",
                )
                self._set_session_secret(hk.derive(shared), "ecdh", session_context)
                return True
            except Exception:
                return False

        if hs_mode == self.HS_PSK:
            self._set_psk_session(session_context)
            return True
        return False

    def _set_psk_session(self, session_context: str) -> None:
        shared = hmac.new(
            self.shared_secret.encode(),
            f"OMNIGUARD_V2X_PSK_V1|{session_context}".encode(),
            hashlib.sha256,
        ).digest()
        self._set_session_secret(shared, "psk", session_context)

    def _set_session_secret(self, shared_secret: bytes, context: str, session_context: str):
        digest = hmac.new(
            self.shared_secret.encode(),
            b"OMNIGUARD_V2X_SESSION_V1|" + bytes(shared_secret),
            hashlib.sha3_256,
        ).digest()
        self._session_key = digest
        self._session_id = hashlib.sha3_256(
            f"{context}|{session_context}|".encode() + digest
        ).hexdigest()[:24]
        if context.startswith("pqc_kem"):
            self._hs_mode = self.HS_PQC_KEM
            self._negotiated_kem_alg = context.split(":", 1)[1] if ":" in context else ""
        elif context == "ecdh":
            self._hs_mode = self.HS_ECDH
            self._negotiated_kem_alg = ""
        else:
            self._hs_mode = self.HS_PSK
            self._negotiated_kem_alg = ""

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

        score = self._agility_score(recommended_mode)
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

    def _require_session(self) -> None:
        if not self.session_established:
            raise RuntimeError("V2X cryptographic session is not established")

    def sign_message(self, msg_without_security: Dict[str, Any]) -> Dict[str, Any]:
        self._require_session()
        canonical = _canonical_json(msg_without_security).encode()
        sec: Dict[str, Any] = {
            "mode": self.mode,
            "hs_mode": self._hs_mode,
            "session_id": self._session_id,
        }

        if self.mode == self.MODE_DILITHIUM:
            signature = self._sign_dilithium(canonical)
            if signature and self._dilithium_pk_hex:
                sec.update({
                    "signature": signature,
                    "pubkey": self._dilithium_pk_hex,
                    "scheme": self._pqc_sig_alg.upper(),
                })
                return sec
            ecdsa_sig = self._sign_ecdsa(canonical)
            if ecdsa_sig:
                sec.update({
                    "signature": ecdsa_sig,
                    "pubkey": self._ecdsa_pub_hex,
                    "scheme": "ECDSA-SECP256R1",
                })
                return sec

        sec.update({
            "signature": hmac.new(self._session_key, canonical, hashlib.sha3_256).hexdigest(),
            "scheme": "HMAC-SHA3-256",
        })
        return sec

    def verify_message(
        self,
        msg: Dict[str, Any],
        *,
        expected_sender_id: str = "",
        replay_cache: Optional[Dict[str, float]] = None,
        max_skew_sec: int = DEFAULT_REPLAY_WINDOW_SEC,
    ) -> bool:
        if not self.session_established or not isinstance(msg, dict):
            return False
        if expected_sender_id and str(msg.get("sender_id", "")) != expected_sender_id:
            return False
        if not _fresh_timestamp(msg.get("timestamp", ""), max_skew_sec):
            return False
        nonce = str(msg.get("nonce", ""))

        sec = msg.get("security")
        if not isinstance(sec, dict):
            return False
        if not hmac.compare_digest(str(sec.get("session_id", "")), self._session_id):
            return False
        signature = str(sec.get("signature", ""))
        scheme = str(sec.get("scheme", "")).upper()
        if not signature or not scheme:
            return False

        bare = dict(msg)
        bare.pop("security", None)
        bare.pop("hub_security", None)
        canonical = _canonical_json(bare).encode()

        valid = False
        if scheme == "HMAC-SHA3-256":
            if self._peer_sig_scheme and self._peer_sig_scheme != "HMAC-SHA3-256":
                return False
            expected = hmac.new(self._session_key, canonical, hashlib.sha3_256).hexdigest()
            valid = hmac.compare_digest(signature, expected)
        elif scheme == "ECDSA-SECP256R1":
            pubkey = str(sec.get("pubkey", ""))
            valid = (
                self._peer_sig_scheme == scheme
                and bool(self._peer_sig_pubkey)
                and hmac.compare_digest(pubkey, self._peer_sig_pubkey)
                and self._verify_ecdsa(canonical, signature, self._peer_sig_pubkey)
            )
        else:
            pubkey = str(sec.get("pubkey", ""))
            valid = (
                self._peer_sig_scheme == scheme
                and bool(self._peer_sig_pubkey)
                and hmac.compare_digest(pubkey, self._peer_sig_pubkey)
                and self._verify_dilithium(canonical, signature, self._peer_sig_pubkey)
            )

        if not valid:
            return False
        return _claim_nonce(replay_cache, nonce, max_skew_sec)

    def sign_forwarded_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate a hub-to-recipient forwarding decision with recipient session key."""
        self._require_session()
        envelope = {
            "scheme": "HMAC-SHA3-256",
            "session_id": self._session_id,
            "forwarded_at": _now(),
            "nonce": _make_nonce(),
        }
        signed = {"message": message, "hub_security": envelope}
        envelope["signature"] = hmac.new(
            self._session_key, _canonical_json(signed).encode(), hashlib.sha3_256
        ).hexdigest()
        return envelope

    def verify_forwarded_message(
        self,
        message: Dict[str, Any],
        *,
        replay_cache: Optional[Dict[str, float]] = None,
        max_skew_sec: int = DEFAULT_REPLAY_WINDOW_SEC,
    ) -> bool:
        if not self.session_established or not isinstance(message, dict):
            return False
        sec = message.get("hub_security")
        if not isinstance(sec, dict):
            return False
        if str(sec.get("scheme", "")).upper() != "HMAC-SHA3-256":
            return False
        if not hmac.compare_digest(str(sec.get("session_id", "")), self._session_id):
            return False
        if not _fresh_timestamp(sec.get("forwarded_at", ""), max_skew_sec):
            return False
        hub_nonce = str(sec.get("nonce", ""))
        signature = str(sec.get("signature", ""))
        if not signature:
            return False
        bare_sec = dict(sec)
        bare_sec.pop("signature", None)
        bare_message = dict(message)
        bare_message.pop("hub_security", None)
        signed = {"message": bare_message, "hub_security": bare_sec}
        expected = hmac.new(
            self._session_key, _canonical_json(signed).encode(), hashlib.sha3_256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        return _claim_nonce(replay_cache, hub_nonce, max_skew_sec)

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
                return False
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
            pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), bytes.fromhex(pub_hex)
            )
            pub.verify(base64.b64decode(sig_b64.encode()), payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def _prepare_kem_keypair(self):
        self._kem_alg = ""
        self._kem_pub_hex = ""
        self._kem_sk = None
        self._kem_enabled_mechanisms = []
        self._kem_enabled_mechanisms_upper = set()
        if oqs is None or self._force_classic:
            return
        self._kem_enabled_mechanisms = self._detect_enabled_kem_mechanisms()
        self._kem_enabled_mechanisms_upper = {item.upper() for item in self._kem_enabled_mechanisms}
        for alg in self._pqc_kem_candidates:
            if not self._is_kem_supported(alg):
                continue
            try:
                kem = oqs.KeyEncapsulation(alg)
                self._kem_pub_hex = kem.generate_keypair().hex()
                self._kem_sk = kem.export_secret_key()
                self._kem_alg = alg
                return
            except Exception:
                continue

    def _detect_enabled_kem_mechanisms(self) -> List[str]:
        if oqs is None:
            return []
        for fn_name in (
            "get_enabled_kem_mechanisms",
            "get_enabled_KEM_mechanisms",
            "get_supported_kem_mechanisms",
            "get_supported_KEM_mechanisms",
        ):
            fn = getattr(oqs, fn_name, None)
            if callable(fn):
                try:
                    values = fn()
                    if isinstance(values, (list, tuple)):
                        return [str(value) for value in values]
                except Exception:
                    continue
        return []

    def _resolve_kem_candidates(self, preferred: str, configured: List[str]) -> List[str]:
        unique: List[str] = []
        seen = set()
        for raw in [preferred] + list(configured):
            alg = self._normalize_kem_alg(raw)
            if not alg or alg.upper() in seen:
                continue
            seen.add(alg.upper())
            unique.append(alg)
        return unique or ["ML-KEM-512", "Kyber512"]

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
        upper = raw.upper().replace("_", "-")
        return aliases.get(upper, raw)

    def _is_kem_supported(self, alg: str) -> bool:
        if oqs is None:
            return False
        candidate = self._normalize_kem_alg(alg)
        if not candidate:
            return False
        if self._kem_enabled_mechanisms_upper and candidate.upper() not in self._kem_enabled_mechanisms_upper:
            return False
        return True


class V2XHub:
    def __init__(
        self,
        host: str = None,
        port: int = None,
        *,
        node_key_registry: Optional[Dict[str, str]] = None,
        shared_secret: Optional[str] = None,
    ):
        self.host = host or get_env("SMARTCAR_V2X_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_V2X_PORT", 9988)
        self.replay_window_sec = max(
            3, get_int("SMARTCAR_V2X_REPLAY_WINDOW_SEC", DEFAULT_REPLAY_WINDOW_SEC)
        )
        self._node_key_registry = dict(node_key_registry or _load_secret_registry("SMARTCAR_V2X_NODE_KEYS_JSON"))
        self._global_secret = ""
        allow_global = get_bool("SMARTCAR_V2X_ALLOW_GLOBAL_PSK", False)
        if self._node_key_registry:
            for node_id, secret in list(self._node_key_registry.items()):
                if not _NODE_ID_RE.fullmatch(str(node_id)):
                    raise RuntimeError("V2X node registry contains an invalid node ID")
                self._node_key_registry[str(node_id)] = _validate_secret(secret, f"V2X node key {node_id}")
        elif shared_secret is not None:
            self._global_secret = _validate_secret(shared_secret, "V2X shared secret")
        elif allow_global:
            self._global_secret = get_required_secret("SMARTCAR_V2X_SHARED_SECRET", min_length=32)
        else:
            raise RuntimeError(
                "Configure SMARTCAR_V2X_NODE_KEYS_JSON for per-node authentication; "
                "global V2X PSK fallback is disabled by default"
            )

        self._running = False
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._clients: Dict[socket.socket, Dict[str, Any]] = {}
        self._hello_replay_cache: Dict[str, float] = {}
        self._msg_ts_hist: Deque[float] = deque(maxlen=1024)
        self._latency_hint_ms = float(get_env("SMARTCAR_V2X_HUB_LATENCY_HINT_MS", "20.0"))

    def _node_secret(self, node_id: str) -> str:
        if self._node_key_registry:
            secret = self._node_key_registry.get(node_id, "")
            if not secret:
                raise RuntimeError("UNREGISTERED_V2X_NODE")
            return secret
        if self._global_secret:
            return self._global_secret
        raise RuntimeError("V2X trust store is not configured")

    def _node_id_in_use(self, node_id: str, current: socket.socket) -> bool:
        with self._lock:
            return any(
                sock is not current
                and state.get("authenticated")
                and state.get("node_id") == node_id
                for sock, state in self._clients.items()
            )

    def _authenticate_hello(self, msg: Dict[str, Any]) -> Optional[str]:
        if not isinstance(msg, dict) or msg.get("type") != V2XMessageType.HELLO:
            return None
        node_id = str(msg.get("sender_id", "")).strip()
        if not _NODE_ID_RE.fullmatch(node_id):
            return None
        if not isinstance(msg.get("payload"), dict):
            return None
        if not _fresh_timestamp(msg.get("timestamp", ""), self.replay_window_sec):
            return None
        nonce = str(msg.get("nonce", ""))
        supplied = str(msg.get("hello_mac", ""))
        if len(nonce) < 16 or not supplied:
            return None
        try:
            secret = self._node_secret(node_id)
        except RuntimeError:
            return None
        expected = _auth_mac(secret, msg, "hello_mac")
        if not hmac.compare_digest(supplied, expected):
            return None
        if not _claim_nonce(self._hello_replay_cache, nonce, self.replay_window_sec):
            return None
        return secret

    def start(self):
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
            except Exception:
                pass
            raise
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        with self._lock:
            sockets = list(self._clients)
            self._clients.clear()
        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, _addr = self._sock.accept()
                conn.settimeout(1.0)
                with self._lock:
                    self._clients[conn] = {
                        "node_id": "",
                        "node_type": "",
                        "authenticated": False,
                        "crypto": None,
                        "replay_cache": {},
                    }
                threading.Thread(target=self._client_loop, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.warning("V2X accept loop socket error", exc_info=True)
                break

    def _client_loop(self, conn: socket.socket):
        buf = ""
        try:
            while self._running:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                    break
                if not chunk:
                    break
                buf += chunk.decode(errors="replace")
                if len(buf.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
                    logger.warning("V2X client exceeded message buffer limit")
                    break
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if not line.strip():
                        continue
                    msg = parse_message(line)
                    if msg:
                        self._msg_ts_hist.append(time.time())
                        self._handle_msg(conn, msg)
        finally:
            with self._lock:
                self._clients.pop(conn, None)
            try:
                conn.close()
            except Exception:
                pass

    def _handle_msg(self, conn: socket.socket, msg: Dict[str, Any]):
        mtype = str(msg.get("type", ""))
        if mtype == V2XMessageType.HELLO:
            with self._lock:
                state = self._clients.get(conn)
            if not state or state.get("authenticated"):
                return
            secret = self._authenticate_hello(msg)
            node_id = str(msg.get("sender_id", ""))
            if not secret or self._node_id_in_use(node_id, conn):
                logger.warning("V2X HELLO rejected for %s", node_id or "unknown")
                return

            payload = msg.get("payload", {})
            peer_crypto = DynamicCryptoAgilityLayer(
                node_id=f"hub-peer:{node_id}", shared_secret=secret
            )
            if not peer_crypto.pin_peer_identity(payload):
                logger.warning("V2X HELLO missing a valid signing identity for %s", node_id)
                return
            handshake = peer_crypto.accept_handshake_as_server(
                payload, session_context=str(msg.get("nonce", ""))
            )
            if handshake.get("hs_mode") == DynamicCryptoAgilityLayer.HS_NONE or not peer_crypto.session_established:
                return

            with self._lock:
                state = self._clients.get(conn)
                if state is None:
                    return
                state.update({
                    "node_id": node_id,
                    "node_type": str(msg.get("sender_type", "")),
                    "authenticated": True,
                    "crypto": peer_crypto,
                    "replay_cache": {},
                })

            ack = _new_message(
                V2XMessageType.HELLO_ACK,
                "v2x_hub",
                "infrastructure",
                {
                    "status": "CONNECTED",
                    "peer_node_id": node_id,
                    "hub_time": _now(),
                    "recommended_crypto_mode": self._recommend_crypto_mode(),
                    "handshake": handshake,
                },
            )
            ack["ack_mac"] = _auth_mac(secret, ack, "ack_mac")
            self._send_raw(conn, ack)
            return

        with self._lock:
            state = self._clients.get(conn)
        if not state or not state.get("authenticated"):
            logger.warning("Dropping unauthenticated V2X message")
            return
        node_id = str(state.get("node_id", ""))
        if str(msg.get("sender_id", "")) != node_id:
            logger.warning("Dropping V2X sender identity mismatch")
            return
        verifier = state.get("crypto")
        if not isinstance(verifier, DynamicCryptoAgilityLayer):
            return
        if not verifier.verify_message(
            msg,
            expected_sender_id=node_id,
            replay_cache=state.get("replay_cache"),
            max_skew_sec=self.replay_window_sec,
        ):
            logger.warning("Dropping invalid/replayed V2X message from %s", node_id)
            return

        if mtype == V2XMessageType.PING:
            pong = _new_message(
                V2XMessageType.PONG,
                "v2x_hub",
                "infrastructure",
                {"ok": True},
            )
            pong["hub_security"] = verifier.sign_forwarded_message(pong)
            self._send_raw(conn, pong)
            return

        self._broadcast(msg, exclude=conn)

    def _send_raw(self, conn: socket.socket, message: Dict[str, Any]) -> bool:
        try:
            conn.sendall((_canonical_json(message) + "\n").encode())
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return False

    def _recommend_crypto_mode(self) -> str:
        now = time.time()
        cutoff = now - 4.0
        while self._msg_ts_hist and self._msg_ts_hist[0] < cutoff:
            self._msg_ts_hist.popleft()
        mps = len(self._msg_ts_hist) / 4.0
        with self._lock:
            client_load = len(self._clients)
        score = (
            0.5 * min(1.0, mps / float(max(1, get_int("SMARTCAR_V2X_CRYPTO_TRAFFIC_HIGH_MPS", 60))))
            + 0.3 * min(1.0, client_load / 24.0)
            + 0.2 * min(1.0, self._latency_hint_ms / float(max(1, get_int("SMARTCAR_V2X_CRYPTO_LATENCY_HIGH_MS", 120))))
        )
        return DynamicCryptoAgilityLayer.MODE_SHA3 if score >= 0.66 else DynamicCryptoAgilityLayer.MODE_DILITHIUM

    def _broadcast(self, msg: Dict[str, Any], exclude: Optional[socket.socket] = None):
        with self._lock:
            targets = list(self._clients.items())
        for sock, state in targets:
            if sock is exclude or not state.get("authenticated"):
                continue
            crypto = state.get("crypto")
            if not isinstance(crypto, DynamicCryptoAgilityLayer):
                continue
            forwarded = dict(msg)
            forwarded.pop("hub_security", None)
            forwarded["hub_security"] = crypto.sign_forwarded_message(forwarded)
            if not self._send_raw(sock, forwarded):
                with self._lock:
                    self._clients.pop(sock, None)
                try:
                    sock.close()
                except Exception:
                    pass


class V2XNode:
    def __init__(
        self,
        node_id: str,
        node_type: str,
        host: str = None,
        port: int = None,
        on_message: Optional[Callable[[Dict], None]] = None,
        *,
        node_secret: Optional[str] = None,
    ):
        self.node_id = str(node_id).strip()
        if not _NODE_ID_RE.fullmatch(self.node_id):
            raise ValueError("node_id contains invalid characters or length")
        self.node_type = str(node_type).strip() or "vehicle"
        self.host = host or get_env("SMARTCAR_V2X_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_V2X_PORT", 9988)
        self.on_message = on_message
        self.replay_window_sec = max(
            3, get_int("SMARTCAR_V2X_REPLAY_WINDOW_SEC", DEFAULT_REPLAY_WINDOW_SEC)
        )

        if node_secret is None:
            direct = get_env("SMARTCAR_V2X_NODE_SECRET", "").strip()
            registry = _load_secret_registry("SMARTCAR_V2X_NODE_KEYS_JSON")
            if direct:
                node_secret = direct
            elif self.node_id in registry:
                node_secret = registry[self.node_id]
            elif get_bool("SMARTCAR_V2X_ALLOW_GLOBAL_PSK", False):
                node_secret = get_required_secret("SMARTCAR_V2X_SHARED_SECRET", min_length=32)
            else:
                raise RuntimeError(
                    "SMARTCAR_V2X_NODE_SECRET is required for node authentication; "
                    "global PSK fallback is disabled by default"
                )
        self.node_secret = _validate_secret(node_secret, "SMARTCAR_V2X_NODE_SECRET")

        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._lock = threading.Lock()
        self._recv_thread: Optional[threading.Thread] = None
        self._hub_replay_cache: Dict[str, float] = {}
        self.crypto_layer = DynamicCryptoAgilityLayer(
            node_id=self.node_id, shared_secret=self.node_secret
        )

    @property
    def connected(self) -> bool:
        return self._connected

    def _build_hello_message(self) -> Dict[str, Any]:
        hello = _new_message(
            V2XMessageType.HELLO,
            self.node_id,
            self.node_type,
            {
                "node_version": "2.0",
                "crypto_capabilities": [
                    "SHA3-HMAC",
                    "DILITHIUM",
                    "PQC_KEM",
                    "AUTHENTICATED_HELLO",
                    "REPLAY_PROTECTION",
                    "ECDH_DISABLED_BY_DEFAULT",
                ],
                "selected_crypto_mode": self.crypto_layer.mode,
                **self.crypto_layer.handshake_hello_payload(),
            },
        )
        hello["hello_mac"] = _auth_mac(self.node_secret, hello, "hello_mac")
        return hello

    def _verify_ack(self, msg: Dict[str, Any]) -> bool:
        if msg.get("type") != V2XMessageType.HELLO_ACK:
            return False
        if str(msg.get("sender_id", "")) != "v2x_hub":
            return False
        if not _fresh_timestamp(msg.get("timestamp", ""), self.replay_window_sec):
            return False
        payload = msg.get("payload")
        if not isinstance(payload, dict) or str(payload.get("peer_node_id", "")) != self.node_id:
            return False
        supplied = str(msg.get("ack_mac", ""))
        if not supplied:
            return False
        expected = _auth_mac(self.node_secret, msg, "ack_mac")
        return hmac.compare_digest(supplied, expected)

    def connect(self, timeout: float = 3.0) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(timeout)
            self._sock.connect((self.host, self.port))
            self._sock.settimeout(1.0)
            t0 = time.perf_counter()
            hello = self._build_hello_message()
            self._sock.sendall((_canonical_json(hello) + "\n").encode())
            raw = self._recv_line()
            msg = parse_message(raw) if raw else None
            if not msg or not self._verify_ack(msg):
                self.disconnect()
                return False

            payload = msg.get("payload", {})
            handshake = payload.get("handshake", {})
            if not self.crypto_layer.complete_handshake_as_client(
                handshake, session_context=str(hello.get("nonce", ""))
            ):
                self.disconnect()
                return False

            self.crypto_layer.observe_latency((time.perf_counter() - t0) * 1000.0)
            self.crypto_layer.maybe_switch_mode(
                str(payload.get("recommended_crypto_mode", ""))
            )
            self._connected = True
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._recv_thread.start()
            return True
        except Exception:
            logger.exception("V2X node connect failed (%s:%s)", self.host, self.port)
            self.disconnect()
            return False

    def disconnect(self):
        self._connected = False
        self._hub_replay_cache.clear()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _recv_line(self) -> Optional[str]:
        if not self._sock:
            return None
        buf = ""
        while "\n" not in buf:
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                continue
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk.decode(errors="replace")
            if len(buf.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
                return None
        return buf.split("\n", 1)[0]

    def _recv_loop(self):
        if not self._sock:
            return
        buf = ""
        while self._connected:
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                continue
            except Exception:
                self._connected = False
                break
            if not chunk:
                self._connected = False
                break
            buf += chunk.decode(errors="replace")
            if len(buf.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
                self._connected = False
                break
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if not line.strip():
                    continue
                msg = parse_message(line)
                if not msg:
                    continue
                if not self.crypto_layer.verify_forwarded_message(
                    msg,
                    replay_cache=self._hub_replay_cache,
                    max_skew_sec=self.replay_window_sec,
                ):
                    logger.warning("Dropping unauthenticated/replayed hub-forwarded V2X message")
                    continue
                self.crypto_layer.observe_message()
                payload = msg.get("payload", {}) if isinstance(msg.get("payload"), dict) else {}
                self.crypto_layer.maybe_switch_mode(
                    str(payload.get("recommended_crypto_mode", ""))
                )
                if self.on_message:
                    try:
                        self.on_message(msg)
                    except Exception:
                        logger.exception("V2X on_message callback error")

    def send(self, msg_type: str, payload: Dict) -> bool:
        if not self._connected or not self._sock or not self.crypto_layer.session_established:
            return False
        if not isinstance(payload, dict):
            return False
        switched = self.crypto_layer.maybe_switch_mode()
        if switched:
            logger.info("V2X crypto mode switched to %s for %s", switched, self.node_id)
        base = _new_message(msg_type, self.node_id, self.node_type, payload)
        base["security"] = self.crypto_layer.sign_message(base)
        data = (_canonical_json(base) + "\n").encode()
        with self._lock:
            try:
                self._sock.sendall(data)
                self.crypto_layer.observe_message()
                return True
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                self._connected = False
                return False

    def send_v2v_telemetry(
        self, speed: float, lat: float, lon: float, heading: float = 0.0
    ) -> bool:
        return self.send(
            V2XMessageType.V2V_TELEMETRY,
            {
                "speed": round(float(speed), 2),
                "lat": round(float(lat), 6),
                "lon": round(float(lon), 6),
                "heading": round(float(heading), 2),
            },
        )

    def send_v2i_signal(
        self,
        intersection_id: str,
        signal_state: str,
        ttl_sec: int = 10,
        extra_payload: Optional[Dict] = None,
    ) -> bool:
        payload = {
            "intersection_id": intersection_id,
            "signal_state": signal_state,
            "ttl_sec": int(ttl_sec),
        }
        if extra_payload:
            payload.update(extra_payload)
        return self.send(V2XMessageType.V2I_SIGNAL, payload)


if __name__ == "__main__":
    print(
        "OmniGuard V2X secure transport. Configure per-node V2X credentials before starting the hub."
    )
