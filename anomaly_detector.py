# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Lightweight anomaly detector for SmartCar telemetry/security streams.

No heavy ML dependency is required. The detector uses:
1) Rolling statistical baseline (z-score per feature)
2) Sudden-change checks
3) Security-pattern heuristics (auth failures, chain integrity failures)
"""

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional
import math


@dataclass
class AnomalyResult:
    is_anomaly: bool
    score: float
    threshold: float
    reasons: List[str]


class LightweightAnomalyDetector:
    def __init__(self, window_size: int = 30, threshold: float = 3.0):
        self.window_size = max(10, window_size)
        self.threshold = threshold
        self.history: Deque[Dict[str, float]] = deque(maxlen=self.window_size)
        self.last_speed: Optional[float] = None

    def _mean_std(self, key: str) -> (float, float):
        vals = [x[key] for x in self.history]
        if not vals:
            return 0.0, 1.0
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / max(1, len(vals) - 1)
        std = math.sqrt(var) if var > 0 else 1.0
        return mean, std

    def detect_telemetry(self, telemetry: Dict[str, float]) -> AnomalyResult:
        reasons: List[str] = []
        score = 0.0

        speed = float(telemetry.get("speed", 0.0))
        accel = float(telemetry.get("acceleration", 0.0))
        temp = float(telemetry.get("engine_temp", 0.0))
        rpm = float(telemetry.get("rpm", 0.0))
        obstacle = float(telemetry.get("obstacle_distance", 999.0))

        # Hard constraints (domain heuristics)
        if speed > 220:
            reasons.append("speed_out_of_range")
            score += 2.0
        if temp > 115:
            reasons.append("engine_temp_critical")
            score += 1.5
        if rpm > 7500:
            reasons.append("rpm_critical")
            score += 1.5
        if abs(accel) > 12:
            reasons.append("acceleration_spike")
            score += 1.2

        if self.last_speed is not None and abs(speed - self.last_speed) > 45:
            reasons.append("speed_jump")
            score += 1.0
        self.last_speed = speed

        # Statistical anomaly only after enough baseline samples
        feature_vec = {
            "speed": speed,
            "acceleration": accel,
            "engine_temp": temp,
            "rpm": rpm,
            "obstacle_distance": obstacle,
        }
        if len(self.history) >= 8:
            zsum = 0.0
            zkeys = ("speed", "acceleration", "engine_temp", "rpm")
            for k in zkeys:
                mean, std = self._mean_std(k)
                z = abs((feature_vec[k] - mean) / std)
                zsum += z
                if z > 3.5:
                    reasons.append(f"zscore_{k}_high")
            score += zsum / len(zkeys)

        self.history.append(feature_vec)
        is_anomaly = score >= self.threshold or len(reasons) >= 2
        return AnomalyResult(is_anomaly=is_anomaly, score=round(score, 3),
                             threshold=self.threshold, reasons=sorted(set(reasons)))

    def detect_security_event(self, event: str, failed_auth_attempts: int = 0) -> AnomalyResult:
        reasons: List[str] = []
        score = 0.0
        ev = event.upper()

        if "AUTH:FAIL" in ev:
            score += 1.0
            reasons.append("auth_failure")
        if failed_auth_attempts >= 2:
            score += 1.2
            reasons.append("repeated_auth_failure")
        if "LOCKOUT" in ev:
            score += 1.5
            reasons.append("lockout_triggered")
        if "CHAIN_COMPROMISED" in ev or "CHAIN_FAIL" in ev:
            score += 2.0
            reasons.append("chain_integrity_threat")
        if "BLOCKED" in ev:
            score += 1.0
            reasons.append("security_block")

        return AnomalyResult(
            is_anomaly=score >= self.threshold or "chain_integrity_threat" in reasons,
            score=round(score, 3),
            threshold=self.threshold,
            reasons=sorted(set(reasons)),
        )

