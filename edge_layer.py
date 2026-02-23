# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Edge telemetry pre-processing layer.

Aggregates raw telemetry locally and emits compact summaries for blockchain write.
"""

import time
from collections import deque
from typing import Dict, List, Optional, Tuple, Deque, Any


class EdgeTelemetryLayer:
    def __init__(
        self,
        enabled: bool = True,
        window_size: int = 5,
        flush_interval_sec: float = 2.0,
        forensic_queue_size: int = 2400,
        forensic_window_sec: int = 600,
    ):
        self.enabled = enabled
        self.window_size = max(1, int(window_size))
        self.flush_interval_sec = max(0.1, float(flush_interval_sec))
        self._buffer: List[Tuple[dict, str]] = []
        self._last_flush_ts = time.time()
        self.forensic_window_sec = max(60, int(forensic_window_sec))
        self._forensic_queue: Deque[Dict[str, Any]] = deque(maxlen=max(100, int(forensic_queue_size)))

    def record_forensic_sample(self, telemetry: dict, event_hint: str = ""):
        self._forensic_queue.append({
            "timestamp": telemetry.get("timestamp", ""),
            "event": event_hint or "TELEMETRY:UPDATE",
            "telemetry": dict(telemetry),
            "ingest_ts": time.time(),
        })

    def _avg(self, vals: List[float]) -> float:
        if not vals:
            return 0.0
        return float(sum(vals) / len(vals))

    def _flush(self, event_hint: str = "") -> Optional[Dict]:
        if not self._buffer:
            return None

        telemetry_list = [t for t, _ in self._buffer]
        events = [e for _, e in self._buffer if e]

        speed_vals = [float(t.get("speed", 0.0)) for t in telemetry_list]
        accel_vals = [float(t.get("acceleration", 0.0)) for t in telemetry_list]
        fuel_vals = [float(t.get("fuel_level", 0.0)) for t in telemetry_list]
        batt_vals = [float(t.get("battery_voltage", 0.0)) for t in telemetry_list]
        temp_vals = [float(t.get("engine_temp", 0.0)) for t in telemetry_list]
        lat_vals = [float(t.get("gps_lat", 0.0)) for t in telemetry_list]
        lon_vals = [float(t.get("gps_lon", 0.0)) for t in telemetry_list]
        obs_vals = [float(t.get("obstacle_distance", 999.0)) for t in telemetry_list]
        steer_vals = [float(t.get("steering_angle", 0.0)) for t in telemetry_list]
        brake_vals = [float(t.get("brake_pressure", 0.0)) for t in telemetry_list]
        thr_vals = [float(t.get("throttle_position", 0.0)) for t in telemetry_list]
        rpm_vals = [float(t.get("rpm", 0.0)) for t in telemetry_list]
        odo_vals = [float(t.get("odometer", 0.0)) for t in telemetry_list]
        ebrake_vals = [bool(t.get("emergency_brake_active", False)) for t in telemetry_list]
        hr_vals = [float(t.get("driver_heart_rate_bpm", 0.0)) for t in telemetry_list]
        drowsy_vals = [float(t.get("driver_drowsiness_score", 0.0)) for t in telemetry_list]
        unwell_vals = [bool(t.get("driver_unwell", False)) for t in telemetry_list]

        summary_telemetry = {
            "speed": self._avg(speed_vals),
            "acceleration": self._avg(accel_vals),
            "fuel_level": fuel_vals[-1] if fuel_vals else 0.0,
            "battery_voltage": self._avg(batt_vals),
            "engine_temp": self._avg(temp_vals),
            "gps_lat": self._avg(lat_vals),
            "gps_lon": self._avg(lon_vals),
            "obstacle_distance": min(obs_vals) if obs_vals else 999.0,
            "emergency_brake_active": any(ebrake_vals),
            "steering_angle": self._avg(steer_vals),
            "brake_pressure": max(brake_vals) if brake_vals else 0.0,
            "throttle_position": self._avg(thr_vals),
            "rpm": self._avg(rpm_vals),
            "odometer": odo_vals[-1] if odo_vals else 0.0,
            "driver_heart_rate_bpm": self._avg(hr_vals) if hr_vals else 0.0,
            "driver_drowsiness_score": max(drowsy_vals) if drowsy_vals else 0.0,
            "driver_unwell": any(unwell_vals),
            "timestamp": telemetry_list[-1].get("timestamp", ""),
        }

        summary_meta = {
            "window_count": len(self._buffer),
            "speed_avg": summary_telemetry["speed"],
            "speed_max": max(speed_vals) if speed_vals else 0.0,
            "speed_min": min(speed_vals) if speed_vals else 0.0,
            "engine_temp_avg": summary_telemetry["engine_temp"],
            "engine_temp_max": max(temp_vals) if temp_vals else 0.0,
            "obstacle_min": summary_telemetry["obstacle_distance"],
            "heart_rate_avg": summary_telemetry["driver_heart_rate_bpm"],
            "drowsiness_max": summary_telemetry["driver_drowsiness_score"],
            "event_count": len(events),
        }

        parts = ["EDGE:SUMMARY"]
        if event_hint:
            parts.append(event_hint)
        if events:
            parts.append(events[-1])
        summary_event = "|".join(parts)

        self._buffer.clear()
        self._last_flush_ts = time.time()
        return {
            "telemetry": summary_telemetry,
            "event": summary_event,
            "meta": summary_meta,
        }

    def ingest(self, telemetry: dict, event_hint: str = "") -> Optional[Dict]:
        now = time.time()
        self.record_forensic_sample(telemetry, event_hint)

        if not self.enabled:
            return {
                "telemetry": telemetry,
                "event": event_hint or "TELEMETRY:UPDATE",
                "meta": {"window_count": 1, "bypass": True},
            }

        self._buffer.append((dict(telemetry), event_hint))
        if len(self._buffer) >= self.window_size:
            return self._flush(event_hint)
        if now - self._last_flush_ts >= self.flush_interval_sec:
            return self._flush(event_hint)
        return None

    def force_flush(self, event_hint: str = "EDGE:FORCE_FLUSH") -> Optional[Dict]:
        return self._flush(event_hint=event_hint)

    def build_forensic_block(self, trigger_event: str, reason: str = "IMPACT") -> Optional[Dict]:
        """
        Build a special FORENSIC_BLOCK payload from recent raw edge queue.
        Intended to be pushed to chain immediately after critical impact/hack events.
        """
        if not self._forensic_queue:
            return None

        now = time.time()
        cutoff = now - self.forensic_window_sec
        records = [r for r in self._forensic_queue if float(r.get("ingest_ts", 0.0)) >= cutoff]
        if not records:
            return None

        last_tel = dict(records[-1].get("telemetry", {}))
        forensic_event = f"FORENSIC_BLOCK:{reason}:{trigger_event}"
        forensic_meta = {
            "forensic_block": True,
            "forensic_reason": reason,
            "trigger_event": trigger_event,
            "window_sec": self.forensic_window_sec,
            "record_count": len(records),
            "records": records,
        }
        return {
            "telemetry": last_tel,
            "event": forensic_event,
            "meta": forensic_meta,
        }

