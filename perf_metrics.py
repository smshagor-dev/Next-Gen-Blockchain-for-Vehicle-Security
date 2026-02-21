# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Performance metric logging utilities.
"""

import json
import threading
import os
from datetime import datetime, timezone

try:
    from env_config import load_project_env_once, get_env
except Exception:
    from env_config import load_project_env_once, get_env

load_project_env_once()

_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_zkp_latency(operation: str, phase: str, latency_ms: float, extra: dict = None):
    path = get_env("SMARTCAR_ZKP_LATENCY_LOG", "logs/zkp_latency.jsonl")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    record = {
        "timestamp": _now(),
        "type": "zkp_latency",
        "operation": operation,
        "phase": phase,
        "latency_ms": round(float(latency_ms), 4),
    }
    if extra:
        record["extra"] = extra
    line = json.dumps(record, separators=(",", ":"))
    with _LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

