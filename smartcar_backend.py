# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
"""Backend adapter for keeping Python focused on GUI work.

Default mode uses the Go HTTP backend for low-latency state/telemetry APIs.
Set SMARTCAR_BACKEND=python to force the original in-process Python core.
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from blockchain import SmartCarBlockchain, TelemetryData
from env_config import get_env


@dataclass
class BackendBlock:
    index: int
    timestamp: str
    vehicle_id: str
    event_data: str
    block_hash: str
    previous_hash: str = ""
    smart_contract_receipts: List[Dict[str, Any]] = None


class PythonBackend:
    def __init__(self, vehicle_id: str, password: str, auth_token: str, chain_file: str):
        self._core = SmartCarBlockchain(vehicle_id, password, auth_token, chain_file=chain_file)

    def __getattr__(self, name: str):
        return getattr(self._core, name)


class GoBackend:
    def __init__(self, vehicle_id: str, password: str, auth_token: str, chain_file: str):
        self.vehicle_id = vehicle_id
        self.password = password
        self.auth_token = auth_token
        self.chain_file = chain_file
        self.base_url = get_env("SMARTCAR_GO_API_URL", "http://127.0.0.1:8787")
        self.chain: List[BackendBlock] = []
        self.car_unlocked = False
        self.engine_started = False
        self.emergency_brake_active = False
        self.safe_mode_active = False
        self._proc = None
        self._ensure_service()
        self._post("/init", {
            "vehicle_id": vehicle_id,
            "password": password,
            "auth_token": auth_token,
            "chain_file": chain_file,
        })
        self._refresh()

    def _ensure_service(self):
        if self._health():
            return
        root = Path(__file__).resolve().parent
        go_root = root / "api" / "go"
        exe = root / "build" / ("smartcar_go_backend.exe" if os.name == "nt" else "smartcar_go_backend")
        if exe.exists():
            cmd = [str(exe)]
            cwd = str(root)
        else:
            cmd = ["go", "run", "."]
            cwd = str(go_root)
        flags = 0
        if os.name == "nt":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
        deadline = time.time() + 12.0
        while time.time() < deadline:
            if self._health():
                return
            time.sleep(0.25)
        raise RuntimeError("Go backend did not become ready on http://127.0.0.1:8787")

    def _health(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.base_url}/health", timeout=0.35) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _request(self, method: str, path: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Go backend HTTP {e.code}: {detail}") from e

    def _get(self, path: str) -> Dict[str, Any]:
        return self._request("GET", path)

    def _post(self, path: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
        return self._request("POST", path, payload or {})

    def _refresh(self):
        status = self._get("/status")
        self.car_unlocked = bool(status.get("car_unlocked", False))
        self.engine_started = bool(status.get("engine_started", False))
        self.emergency_brake_active = bool(status.get("emergency_brake_active", False))
        self.safe_mode_active = bool(status.get("safe_mode_active", False))
        self.chain = [
            BackendBlock(
                index=int(b.get("index", 0)),
                timestamp=str(b.get("timestamp", "")),
                vehicle_id=str(b.get("vehicle_id", self.vehicle_id)),
                event_data=str(b.get("event_data", "")),
                block_hash=str(b.get("block_hash", "")),
                previous_hash=str(b.get("previous_hash", "")),
                smart_contract_receipts=b.get("smart_contract_receipts") or [],
            )
            for b in status.get("chain", [])
        ]

    @staticmethod
    def _telemetry_payload(telemetry: TelemetryData) -> Dict[str, Any]:
        return telemetry.__dict__.copy()

    def authenticate(self, token: str) -> Dict[str, Any]:
        result = self._post("/auth", {"token": token})
        self._refresh()
        return result

    def start_engine(self) -> Dict[str, Any]:
        result = self._post("/engine/start")
        self._refresh()
        return result

    def stop_engine(self):
        result = self._post("/engine/stop")
        self._refresh()
        return result

    def lock_car(self):
        result = self._post("/vehicle/lock")
        self._refresh()
        return result

    def owner_recover_unlock(self, key: str, force_chain_reset: bool = False) -> Dict[str, Any]:
        result = self._post("/recovery/unlock", {"key": key, "force_chain_reset": force_chain_reset})
        self._refresh()
        return result

    def emergency_brake(self, distance: float):
        result = self._post("/emergency/brake", {"distance": distance})
        self._refresh()
        return result

    def push_telemetry(self, telemetry: TelemetryData, event: str = ""):
        result = self._post("/telemetry", {"event": event, "telemetry": self._telemetry_payload(telemetry)})
        self._refresh()
        return result

    def verify_chain(self) -> bool:
        return bool(self._get("/verify").get("valid", False))

    def save(self):
        return self._post("/save")


def create_backend(vehicle_id: str, password: str, auth_token: str, chain_file: str):
    mode = get_env("SMARTCAR_BACKEND", "go").strip().lower()
    if mode == "python":
        return PythonBackend(vehicle_id, password, auth_token, chain_file)
    try:
        return GoBackend(vehicle_id, password, auth_token, chain_file)
    except Exception:
        if get_env("SMARTCAR_BACKEND_STRICT", "0") == "1":
            raise
        return PythonBackend(vehicle_id, password, auth_token, chain_file)
