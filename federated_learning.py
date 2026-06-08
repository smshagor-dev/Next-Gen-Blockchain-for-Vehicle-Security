# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Decentralized federated-learning primitives for obstacle risk model.

Real training path:
- each car performs local SGD (logistic regression) on local telemetry labels
- car shares only weight delta on-chain
- trainer node can aggregate updates (FedAvg) and also fine-tune global model
"""

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np

PROTOTYPE_FL_WARNING = "WARNING: This FL experiment is too small for Byzantine-robustness claims."

FL_VALIDATION_METADATA = {
    "fl_validation_level": "prototype_sanity_check",
    "num_peers": 3,
    "samples_per_peer": 10,
    "test_samples": 24,
    "byzantine_peers": 1,
    "attack_type": "100x_weight_delta",
    "statistical_significance": False,
    "supports_byzantine_robustness_claim": False,
}


def fl_validation_metadata(num_peers: int = 3, test_samples: int = 24) -> Dict:
    """Return conservative metadata for the current prototype FL sanity check."""
    meta = dict(FL_VALIDATION_METADATA)
    meta["num_peers"] = int(num_peers)
    meta["test_samples"] = int(test_samples)
    warnings = []
    if meta["num_peers"] < 5 or meta["test_samples"] < 100:
        warnings.append(PROTOTYPE_FL_WARNING)
    meta["warnings"] = warnings
    return meta


def print_prototype_fl_sanity_check(num_peers: int = 3, test_samples: int = 24) -> Dict:
    """Print the current small FL run label and limitation warning."""
    meta = fl_validation_metadata(num_peers=num_peers, test_samples=test_samples)
    print("=== Prototype FL Sanity Check ===")
    for warning in meta.get("warnings", []):
        print(warning)
    return meta


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clip(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, float(v)))


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -40.0, 40.0)))


FEATURE_KEYS = [
    "near_obstacle",
    "speed_norm",
    "accel_norm",
    "brake_norm",
    "temp_norm",
    "drowsy_norm",
    "hr_risk",
    "bias",
]


@dataclass
class FLModelUpdate:
    vehicle_id: str
    round_id: int
    weights_delta: Dict[str, float]
    sample_count: int
    trigger: str
    timestamp: str
    payload_hash_sha3: str
    local_loss: float
    dp_enabled: bool
    dp_noise_sigma: float
    delta_clip_norm: float

    def to_dict(self) -> Dict:
        return asdict(self)


class FederatedObstacleLearner:
    """
    On-device logistic-regression model for risk prediction.
    """

    def __init__(self, vehicle_id: str):
        self.vehicle_id = vehicle_id
        self.round_id = 0
        self.learning_rate = 0.05
        self.local_epochs = 3
        self.min_samples_per_update = 12
        self.max_buffer = 2048
        self.dp_enabled = True
        self.dp_noise_sigma = 0.010
        self.delta_clip_norm = 0.25
        self.remote_delta_max_norm = 0.65
        self.feature_keys = list(FEATURE_KEYS)
        self.weights = np.array([0.90, 0.26, 0.14, 0.32, 0.10, 0.18, 0.42, 0.02], dtype=np.float64)
        self._sample_buffer: List[Tuple[np.ndarray, float]] = []

    def ingest_sample(self, telemetry: Dict[str, float], event: str):
        x = self._extract_features(telemetry)
        y = self._infer_label(telemetry, event)
        self._sample_buffer.append((x, y))
        if len(self._sample_buffer) > self.max_buffer:
            self._sample_buffer = self._sample_buffer[-self.max_buffer:]

    def maybe_create_local_update(self, trigger_event: str = "PERIODIC") -> Optional[FLModelUpdate]:
        if len(self._sample_buffer) < self.min_samples_per_update:
            return None

        batch = self._sample_buffer[-self.min_samples_per_update:]
        x = np.vstack([p[0] for p in batch])
        y = np.array([p[1] for p in batch], dtype=np.float64)

        before = self.weights.copy()
        loss = self._train_batch(x, y, epochs=self.local_epochs)
        delta = self.weights - before
        delta = self._clip_delta(delta, clip_norm=self.delta_clip_norm)
        if self.dp_enabled and self.dp_noise_sigma > 0.0:
            delta = delta + np.random.normal(0.0, self.dp_noise_sigma, size=delta.shape)
            delta = self._clip_delta(delta, clip_norm=self.delta_clip_norm * 1.25)
        # Re-apply post-processed delta to model.
        self.weights = before + delta

        self.round_id += 1
        delta_dict = self._vector_to_dict(delta)
        payload_base = {
            "vehicle_id": self.vehicle_id,
            "round_id": self.round_id,
            "weights_delta": delta_dict,
            "sample_count": int(len(batch)),
            "trigger": trigger_event,
            "timestamp": _now(),
            "local_loss": round(float(loss), 6),
            "dp_enabled": bool(self.dp_enabled),
            "dp_noise_sigma": float(self.dp_noise_sigma),
            "delta_clip_norm": float(self.delta_clip_norm),
        }
        payload_hash = hashlib.sha3_256(
            json.dumps(payload_base, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return FLModelUpdate(
            vehicle_id=self.vehicle_id,
            round_id=self.round_id,
            weights_delta=delta_dict,
            sample_count=int(len(batch)),
            trigger=trigger_event,
            timestamp=payload_base["timestamp"],
            payload_hash_sha3=payload_hash,
            local_loss=payload_base["local_loss"],
            dp_enabled=payload_base["dp_enabled"],
            dp_noise_sigma=payload_base["dp_noise_sigma"],
            delta_clip_norm=payload_base["delta_clip_norm"],
        )

    def apply_remote_update(self, update_payload: Dict) -> Dict:
        source = str(update_payload.get("vehicle_id", "unknown"))
        if source == self.vehicle_id:
            return {"applied": False, "reason": "self_update"}

        # Preferred path: apply absolute global weights from trainer.
        if isinstance(update_payload.get("global_weights"), dict):
            gw = self._dict_to_vector(update_payload["global_weights"])
            if gw is None:
                return {"applied": False, "reason": "invalid_global_weights"}
            self.weights = gw
            return {"applied": True, "source_vehicle_id": source, "mode": "global_weights"}

        delta = self._dict_to_vector(update_payload.get("weights_delta", {}))
        if delta is None:
            return {"applied": False, "reason": "missing_delta"}
        norm = float(np.linalg.norm(delta))
        if norm > self.remote_delta_max_norm:
            return {"applied": False, "reason": "delta_norm_outlier", "delta_norm": round(norm, 6)}

        merge_alpha = 0.40
        self.weights = self.weights + (delta * merge_alpha)
        return {
            "applied": True,
            "source_vehicle_id": source,
            "mode": "delta_merge",
            "scaled_delta": self._vector_to_dict(delta * merge_alpha),
        }

    def snapshot(self) -> Dict:
        return {
            "vehicle_id": self.vehicle_id,
            "round_id": self.round_id,
            "weights": self._vector_to_dict(self.weights),
            "buffered_samples": len(self._sample_buffer),
            "model_type": "LOGISTIC_OBSTACLE_FL_V2",
            "learning_rate": self.learning_rate,
            "local_epochs": self.local_epochs,
            "dp_enabled": self.dp_enabled,
            "dp_noise_sigma": self.dp_noise_sigma,
            "delta_clip_norm": self.delta_clip_norm,
        }

    def _extract_features(self, telemetry: Dict[str, float]) -> np.ndarray:
        obstacle_distance = float(telemetry.get("obstacle_distance", 999.0))
        speed = float(telemetry.get("speed", 0.0))
        accel = float(telemetry.get("acceleration", 0.0))
        brake = float(telemetry.get("brake_pressure", 0.0))
        temp = float(telemetry.get("engine_temp", 20.0))
        drowsy = float(telemetry.get("driver_drowsiness_score", 0.0))
        hr = float(telemetry.get("driver_heart_rate_bpm", 72.0))
        hr_risk = 1.0 if (hr <= 45.0 or hr >= 140.0) else 0.0

        near_obstacle = 1.0 if obstacle_distance <= 35.0 else 0.0
        speed_norm = _clip(speed / 180.0, 0.0, 1.0)
        accel_norm = _clip(abs(accel) / 12.0, 0.0, 1.0)
        brake_norm = _clip(brake / 100.0, 0.0, 1.0)
        temp_norm = _clip((temp - 60.0) / 60.0, 0.0, 1.0)
        drowsy_norm = _clip(drowsy, 0.0, 1.0)
        return np.array(
            [near_obstacle, speed_norm, accel_norm, brake_norm, temp_norm, drowsy_norm, hr_risk, 1.0],
            dtype=np.float64,
        )

    def _infer_label(self, telemetry: Dict[str, float], event: str) -> float:
        e = str(event).upper()
        obstacle_distance = float(telemetry.get("obstacle_distance", 999.0))
        drowsy = float(telemetry.get("driver_drowsiness_score", 0.0))
        unwell = bool(telemetry.get("driver_unwell", False))
        emergency = bool(telemetry.get("emergency_brake_active", False))
        risky = (
            "EMERGENCY" in e
            or "IMPACT" in e
            or "COLLISION" in e
            or obstacle_distance <= 22.0
            or emergency
            or drowsy >= 0.85
            or unwell
        )
        return 1.0 if risky else 0.0

    def _train_batch(self, x: np.ndarray, y: np.ndarray, epochs: int) -> float:
        w = self.weights
        n = float(max(1, x.shape[0]))
        for _ in range(max(1, int(epochs))):
            logits = x @ w
            pred = _sigmoid(logits)
            grad = (x.T @ (pred - y)) / n
            w = w - (self.learning_rate * grad)
        self.weights = w
        pred_final = _sigmoid(x @ w)
        eps = 1e-9
        loss = -np.mean(y * np.log(pred_final + eps) + (1.0 - y) * np.log(1.0 - pred_final + eps))
        return float(loss)

    def _vector_to_dict(self, v: np.ndarray) -> Dict[str, float]:
        return {k: round(float(v[i]), 6) for i, k in enumerate(self.feature_keys)}

    @staticmethod
    def _clip_delta(delta: np.ndarray, clip_norm: float) -> np.ndarray:
        c = max(1e-9, float(clip_norm))
        n = float(np.linalg.norm(delta))
        if n <= c:
            return delta
        return delta * (c / n)

    def _dict_to_vector(self, d: Dict) -> Optional[np.ndarray]:
        if not isinstance(d, dict):
            return None
        out = []
        try:
            for k in self.feature_keys:
                out.append(float(d.get(k, 0.0)))
            return np.array(out, dtype=np.float64)
        except Exception:
            return None


class FederatedTrainer:
    """
    Trainer node: aggregates client updates and can train further on trainer data.
    """

    def __init__(self, trainer_id: str = "TRAINER_NODE_1"):
        self.trainer_id = trainer_id
        self.feature_keys = list(FEATURE_KEYS)
        self.global_weights = np.array([0.90, 0.26, 0.14, 0.32, 0.10, 0.18, 0.42, 0.02], dtype=np.float64)
        self.global_round = 0
        self.learning_rate = 0.03
        self.outlier_mad_k = 3.5
        self.trim_ratio = 0.2
        self.max_client_delta_norm = 0.85

    def aggregate_updates(self, updates: List[Dict]) -> Dict:
        valid = []
        deltas: List[np.ndarray] = []
        sample_counts: List[float] = []
        norms: List[float] = []
        dropped_by_norm_gate = 0
        for up in updates:
            delta = self._dict_to_vector(up.get("weights_delta", {}))
            if delta is None:
                continue
            norm = float(np.linalg.norm(delta))
            if norm > self.max_client_delta_norm:
                dropped_by_norm_gate += 1
                continue
            sc = float(max(1, int(up.get("sample_count", 1))))
            valid.append(up)
            deltas.append(delta)
            sample_counts.append(sc)
            norms.append(norm)
        if not deltas:
            return {"ok": False, "reason": "no_valid_updates"}

        keep_mask = self._mad_filter(norms, self.outlier_mad_k)
        kept = [d for d, k in zip(deltas, keep_mask) if k]
        kept_sc = [s for s, k in zip(sample_counts, keep_mask) if k]
        dropped = len(deltas) - len(kept)
        if not kept:
            return {"ok": False, "reason": "all_updates_outlier"}

        agg_delta = self._robust_weighted_trimmed_mean(kept, kept_sc, trim_ratio=self.trim_ratio)
        avg_delta = agg_delta
        self.global_weights = self.global_weights + avg_delta
        self.global_round += 1
        return {
            "ok": True,
            "trainer_id": self.trainer_id,
            "global_round": self.global_round,
            "updates_count": len(valid),
            "updates_kept": len(kept),
            "updates_dropped_norm_gate": dropped_by_norm_gate,
            "updates_dropped_outlier": dropped,
            "aggregated_delta": self._vector_to_dict(avg_delta),
            "global_weights": self._vector_to_dict(self.global_weights),
            "timestamp": _now(),
        }

    def train_trainer(self, trainer_samples: List[Dict], epochs: int = 2) -> Dict:
        if not trainer_samples:
            return {"ok": False, "reason": "empty_trainer_samples"}
        x_list = []
        y_list = []
        for s in trainer_samples:
            x_list.append(self._extract_features(s.get("telemetry", {})))
            y_list.append(1.0 if bool(s.get("label_risk", False)) else 0.0)
        x = np.vstack(x_list)
        y = np.array(y_list, dtype=np.float64)
        self._train_global_batch(x, y, epochs=max(1, int(epochs)))
        return {
            "ok": True,
            "trainer_id": self.trainer_id,
            "global_round": self.global_round,
            "global_weights": self._vector_to_dict(self.global_weights),
            "trained_epochs": int(epochs),
            "timestamp": _now(),
        }

    def export_global_model(self) -> Dict:
        payload = {
            "vehicle_id": self.trainer_id,
            "global_round": self.global_round,
            "global_weights": self._vector_to_dict(self.global_weights),
            "timestamp": _now(),
        }
        payload["payload_hash_sha3"] = hashlib.sha3_256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return payload

    def _extract_features(self, telemetry: Dict[str, float]) -> np.ndarray:
        learner_stub = FederatedObstacleLearner("trainer_stub")
        return learner_stub._extract_features(telemetry)

    def _train_global_batch(self, x: np.ndarray, y: np.ndarray, epochs: int):
        w = self.global_weights
        n = float(max(1, x.shape[0]))
        for _ in range(max(1, int(epochs))):
            pred = _sigmoid(x @ w)
            grad = (x.T @ (pred - y)) / n
            w = w - (self.learning_rate * grad)
        self.global_weights = w
        self.global_round += 1

    def _vector_to_dict(self, v: np.ndarray) -> Dict[str, float]:
        return {k: round(float(v[i]), 6) for i, k in enumerate(self.feature_keys)}

    def _dict_to_vector(self, d: Dict) -> Optional[np.ndarray]:
        if not isinstance(d, dict):
            return None
        try:
            return np.array([float(d.get(k, 0.0)) for k in self.feature_keys], dtype=np.float64)
        except Exception:
            return None

    @staticmethod
    def _mad_filter(vals: List[float], k: float) -> List[bool]:
        if not vals:
            return []
        arr = np.array(vals, dtype=np.float64)
        med = float(np.median(arr))
        mad = float(np.median(np.abs(arr - med))) + 1e-9
        z = np.abs(arr - med) / mad
        return [bool(v <= float(k)) for v in z]

    @staticmethod
    def _robust_weighted_trimmed_mean(deltas: List[np.ndarray], weights: List[float], trim_ratio: float) -> np.ndarray:
        x = np.vstack(deltas)
        w = np.array(weights, dtype=np.float64)
        w = np.maximum(w, 1.0)
        trim = _clip(trim_ratio, 0.0, 0.45)
        d = x.shape[1]
        out = np.zeros(d, dtype=np.float64)
        for j in range(d):
            col = x[:, j]
            order = np.argsort(col)
            sorted_col = col[order]
            sorted_w = w[order]
            n = len(sorted_col)
            cut = int(n * trim)
            lo = cut
            hi = n - cut
            if lo >= hi:
                lo, hi = 0, n
            c = sorted_col[lo:hi]
            cw = sorted_w[lo:hi]
            denom = float(np.sum(cw))
            out[j] = float(np.sum(c * cw) / denom) if denom > 0 else float(np.mean(c))
        return out
