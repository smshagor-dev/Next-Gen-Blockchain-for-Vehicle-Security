# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
"""Backend adapter with authenticated loopback transport for the Go control service."""

import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from blockchain import SmartCarBlockchain, TelemetryData
from consensus_security import consensus_security_metadata
from control_api_security import build_signed_headers, validate_loopback_base_url, verify_service_proof
from env_config import get_env, get_required_secret
from federated_learning import fl_validation_metadata
from identity_security import identity_security_metadata
from ledger_integrity import GoLedgerSnapshotVerifier, LedgerIntegrityError, PythonLedgerIntegrityGuard
from zkp_privacy import pedersen_privacy_metadata
from security_capabilities import (
    adversarial_validation_metadata,
    complexity_boundary_metadata,
    contribution_boundary_metadata,
    reviewer_audit_metadata,
    security_capability_output,
)


@dataclass
class BackendBlock:
    index: int
    timestamp: str
    vehicle_id: str
    telemetry: Dict[str, Any]
    event_data: str
    block_hash: str
    previous_hash: str = ""
    smart_contract_receipts: List[Dict[str, Any]] = None


class PythonBackend:
    def __init__(self, vehicle_id: str, password: str, auth_token: str, chain_file: str):
        self._core = SmartCarBlockchain(vehicle_id, password, auth_token, chain_file=chain_file)
        self._ledger_guard = PythonLedgerIntegrityGuard(self._core).install()

    def __getattr__(self, name: str):
        return getattr(self._core, name)

    def ledger_integrity(self) -> Dict[str, Any]:
        return self._ledger_guard.metadata()

    def security_capabilities(self) -> Dict[str, Any]:
        return security_capability_output(False)

    def identity_security(self) -> Dict[str, Any]:
        return identity_security_metadata()

    def consensus_security(self) -> Dict[str, Any]:
        return consensus_security_metadata()

    def fl_validation(self) -> Dict[str, Any]:
        return fl_validation_metadata()

    def adversarial_validation(self) -> Dict[str, Any]:
        return adversarial_validation_metadata()

    def contribution_boundary(self) -> Dict[str, Any]:
        return contribution_boundary_metadata()

    def complexity_boundary(self) -> Dict[str, Any]:
        return complexity_boundary_metadata()

    def pedersen_privacy(self) -> Dict[str, Any]:
        return pedersen_privacy_metadata()

    def reviewer_audit(self) -> Dict[str, Any]:
        return reviewer_audit_metadata()


class GoBackend:
    def __init__(self, vehicle_id: str, password: str, auth_token: str, chain_file: str):
        self.vehicle_id = str(vehicle_id)
        self.password = str(password)
        self.auth_token = str(auth_token)
        self.chain_file = str(chain_file)
        self.api_secret = get_required_secret("SMARTCAR_GO_API_SECRET", min_length=32)
        self.recovery_key = get_required_secret("SMARTCAR_RECOVERY_KEY", min_length=32)
        self.base_url = validate_loopback_base_url(get_env("SMARTCAR_GO_API_URL", "http://127.0.0.1:8787"))
        self._init_payload = {
            "vehicle_id": self.vehicle_id,
            "password": self.password,
            "auth_token": self.auth_token,
            "recovery_key": self.recovery_key,
            "chain_file": self.chain_file,
        }
        self.chain: List[BackendBlock] = []
        self.car_unlocked = False
        self.engine_started = False
        self.emergency_brake_active = False
        self.safe_mode_active = False
        self._security_capabilities: Dict[str, Any] = security_capability_output(False)
        self._identity_security: Dict[str, Any] = identity_security_metadata()
        self._consensus_security: Dict[str, Any] = consensus_security_metadata()
        self._fl_validation: Dict[str, Any] = fl_validation_metadata()
        self._adversarial_validation: Dict[str, Any] = adversarial_validation_metadata()
        self._contribution_boundary: Dict[str, Any] = contribution_boundary_metadata()
        self._complexity_boundary: Dict[str, Any] = complexity_boundary_metadata()
        self._pedersen_privacy: Dict[str, Any] = pedersen_privacy_metadata()
        self._reviewer_audit: Dict[str, Any] = reviewer_audit_metadata()
        self._proc = None
        self._service_instance = ""
        self._ledger_verifier = GoLedgerSnapshotVerifier(self.vehicle_id)
        self._ensure_service()
        self._initialize_remote_state()
        self._refresh()

    def _spawn_environment(self, root: Path) -> Dict[str, str]:
        env = os.environ.copy()
        env["SMARTCAR_GO_API_SECRET"] = self.api_secret
        env["SMARTCAR_GO_DATA_DIR"] = str((root / "logs").resolve())
        return env

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
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        self._proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
            env=self._spawn_environment(root),
        )
        deadline = time.time() + 12.0
        while time.time() < deadline:
            if self._health():
                return
            if self._proc.poll() is not None:
                raise RuntimeError("Go backend exited before authenticated health verification")
            time.sleep(0.25)
        raise RuntimeError("Authenticated Go backend did not become ready on loopback")

    def _health(self) -> bool:
        challenge = secrets.token_hex(16)
        req = urllib.request.Request(
            f"{self.base_url}/health",
            headers={"X-SmartCar-Challenge": challenge, "Cache-Control": "no-store"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                if resp.status != 200:
                    return False
                payload = json.loads(resp.read().decode("utf-8") or "{}")
        except Exception:
            return False
        proof = str(payload.get("service_proof", ""))
        instance = str(payload.get("instance_id", ""))
        if not instance or not verify_service_proof(self.api_secret, challenge, proof):
            return False
        self._service_instance = instance
        return True

    def _initialize_remote_state(self):
        self._request("POST", "/init", self._init_payload, recover=False)

    def _recover_service(self):
        self._ensure_service()
        self._initialize_remote_state()

    @staticmethod
    def _encode_payload(payload: Dict[str, Any] = None) -> bytes:
        if payload is None:
            return b""
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _build_request(self, method: str, path: str, payload: Dict[str, Any] = None) -> urllib.request.Request:
        if not path.startswith("/"):
            raise ValueError("backend API path must be absolute")
        body = self._encode_payload(payload)
        headers = build_signed_headers(self.api_secret, method, path, body)
        headers["Cache-Control"] = "no-store"
        data = body if method.upper() == "POST" else None
        if method.upper() == "POST":
            headers["Content-Type"] = "application/json"
        return urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method.upper())

    def _request(self, method: str, path: str, payload: Dict[str, Any] = None, recover: bool = True) -> Dict[str, Any]:
        attempts = 2 if recover else 1
        last_error = None
        for attempt in range(attempts):
            req = self._build_request(method, path, payload)
            try:
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    body = resp.read().decode("utf-8")
                    return json.loads(body) if body else {}
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Go backend HTTP {exc.code}: {detail}") from exc
            except (ConnectionError, OSError, TimeoutError, urllib.error.URLError) as exc:
                last_error = exc
                if not recover or attempt + 1 >= attempts:
                    break
                self._recover_service()
        raise RuntimeError(f"Go backend connection unavailable: {last_error}") from last_error

    def _get(self, path: str) -> Dict[str, Any]:
        return self._request("GET", path)

    def _post(self, path: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
        return self._request("POST", path, payload or {})

    def _refresh(self):
        status = self._get("/status")
        raw_chain = status.get("chain", [])
        if not isinstance(raw_chain, list):
            raise LedgerIntegrityError("Go backend returned a non-list ledger")
        self._ledger_verifier.verify_and_track(raw_chain, self._service_instance)
        self.car_unlocked = bool(status.get("car_unlocked", False))
        self.engine_started = bool(status.get("engine_started", False))
        self.emergency_brake_active = bool(status.get("emergency_brake_active", False))
        self.safe_mode_active = bool(status.get("safe_mode_active", False))
        self._security_capabilities = status.get("security_capabilities") or security_capability_output(False)
        self._identity_security = status.get("identity_security") or identity_security_metadata()
        self._consensus_security = status.get("consensus_security") or consensus_security_metadata()
        self._fl_validation = status.get("fl_validation") or fl_validation_metadata()
        self._adversarial_validation = status.get("adversarial_validation") or adversarial_validation_metadata()
        self._contribution_boundary = status.get("contribution_boundary") or contribution_boundary_metadata()
        self._complexity_boundary = status.get("complexity_boundary") or complexity_boundary_metadata()
        self._pedersen_privacy = status.get("pedersen_privacy") or pedersen_privacy_metadata()
        self._reviewer_audit = status.get("reviewer_audit") or reviewer_audit_metadata()
        self.chain = [
            BackendBlock(
                index=int(b.get("index", 0)),
                timestamp=str(b.get("timestamp", "")),
                vehicle_id=str(b.get("vehicle_id", self.vehicle_id)),
                telemetry=dict(b.get("telemetry") or {}),
                event_data=str(b.get("event_data", "")),
                block_hash=str(b.get("block_hash", "")),
                previous_hash=str(b.get("previous_hash", "")),
                smart_contract_receipts=b.get("smart_contract_receipts") or [],
            )
            for b in raw_chain
        ]

    def _assert_remote_ledger_valid(self):
        self._refresh()
        if not bool(self._get("/verify").get("valid", False)):
            raise LedgerIntegrityError("Go backend rejected its own ledger hash chain")

    @staticmethod
    def _telemetry_payload(telemetry: TelemetryData) -> Dict[str, Any]:
        return telemetry.__dict__.copy()

    def authenticate(self, token: str) -> Dict[str, Any]:
        self._assert_remote_ledger_valid()
        result = self._post("/auth", {"token": token})
        self._refresh()
        return result

    def start_engine(self) -> Dict[str, Any]:
        self._assert_remote_ledger_valid()
        result = self._post("/engine/start")
        self._refresh()
        return result

    def stop_engine(self):
        result = self._post("/engine/stop")
        try:
            self._refresh()
        except LedgerIntegrityError as exc:
            self.engine_started = False
            result = dict(result)
            result["ledger_integrity_warning"] = str(exc)
        return result

    def lock_car(self):
        result = self._post("/vehicle/lock")
        try:
            self._refresh()
        except LedgerIntegrityError as exc:
            self.car_unlocked = False
            self.engine_started = False
            result = dict(result)
            result["ledger_integrity_warning"] = str(exc)
        return result

    def owner_recover_unlock(self, key: str, force_chain_reset: bool = False) -> Dict[str, Any]:
        self._assert_remote_ledger_valid()
        result = self._post("/recovery/unlock", {"key": key, "force_chain_reset": force_chain_reset})
        self._refresh()
        return result

    def emergency_brake(self, distance: float):
        result = self._post("/emergency/brake", {"distance": distance})
        try:
            self._refresh()
        except LedgerIntegrityError as exc:
            self.emergency_brake_active = True
            result = dict(result)
            result["ledger_integrity_warning"] = str(exc)
        return result

    def push_telemetry(self, telemetry: TelemetryData, event: str = ""):
        self._assert_remote_ledger_valid()
        result = self._post("/telemetry", {"event": event, "telemetry": self._telemetry_payload(telemetry)})
        self._refresh()
        return result

    def verify_chain(self) -> bool:
        try:
            self._refresh()
            return self._ledger_verifier.last_valid and bool(self._get("/verify").get("valid", False))
        except LedgerIntegrityError:
            return False

    def save(self):
        self._assert_remote_ledger_valid()
        return self._post("/save")

    def ledger_integrity(self) -> Dict[str, Any]:
        return self._ledger_verifier.metadata()

    def security_capabilities(self) -> Dict[str, Any]:
        try:
            self._security_capabilities = self._get("/security/capabilities")
        except Exception:
            pass
        return dict(self._security_capabilities)

    def identity_security(self) -> Dict[str, Any]:
        try:
            self._identity_security = self._get("/identity/security")
        except Exception:
            pass
        return dict(self._identity_security)

    def consensus_security(self) -> Dict[str, Any]:
        try:
            self._consensus_security = self._get("/consensus/security")
        except Exception:
            pass
        return dict(self._consensus_security)

    def fl_validation(self) -> Dict[str, Any]:
        try:
            self._fl_validation = self._get("/fl/validation")
        except Exception:
            pass
        return dict(self._fl_validation)

    def adversarial_validation(self) -> Dict[str, Any]:
        try:
            self._adversarial_validation = self._get("/adversarial/validation")
        except Exception:
            pass
        return dict(self._adversarial_validation)

    def contribution_boundary(self) -> Dict[str, Any]:
        try:
            self._contribution_boundary = self._get("/contribution/boundary")
        except Exception:
            pass
        return dict(self._contribution_boundary)

    def complexity_boundary(self) -> Dict[str, Any]:
        try:
            self._complexity_boundary = self._get("/complexity/boundary")
        except Exception:
            pass
        return dict(self._complexity_boundary)

    def pedersen_privacy(self) -> Dict[str, Any]:
        try:
            self._pedersen_privacy = self._get("/privacy/pedersen")
        except Exception:
            pass
        return dict(self._pedersen_privacy)

    def reviewer_audit(self) -> Dict[str, Any]:
        try:
            self._reviewer_audit = self._get("/reviewer/audit")
        except Exception:
            pass
        return dict(self._reviewer_audit)


def create_backend(vehicle_id: str, password: str, auth_token: str, chain_file: str):
    mode = get_env("SMARTCAR_BACKEND", "go").strip().lower()
    if mode == "python":
        return PythonBackend(vehicle_id, password, auth_token, chain_file)
    try:
        return GoBackend(vehicle_id, password, auth_token, chain_file)
    except Exception:
        if get_env("SMARTCAR_BACKEND_ALLOW_PYTHON_FALLBACK", "0") == "1":
            return PythonBackend(vehicle_id, password, auth_token, chain_file)
        raise
