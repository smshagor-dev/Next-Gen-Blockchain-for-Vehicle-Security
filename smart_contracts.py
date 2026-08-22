# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Dynamic smart-contract integration for SmartCar.

Supports Ethereum/Fabric style connectors via HTTP RPC-style endpoints.
Configuration is fully driven from environment variables.
"""

import hashlib
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, List

try:
    from env_config import load_project_env_once, get_env, get_bool, get_int, get_float
except Exception:
    from env_config import load_project_env_once, get_env, get_bool, get_int, get_float

load_project_env_once()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: Dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ContractConnector:
    def __init__(self, name: str, provider: str, endpoint: str, timeout_sec: int = 4, mock_mode: bool = True):
        self.name = name
        self.provider = provider
        self.endpoint = endpoint
        self.timeout_sec = timeout_sec
        self.mock_mode = mock_mode

    def _deterministic_mock_tx_hash(self, method: str, payload: Dict) -> str:
        material = "\n".join(
            [
                "OMNIGUARD_SMART_CONTRACT_MOCK_V2",
                self.provider,
                self.name,
                method,
                _canonical_json(payload),
            ]
        )
        return "mock_" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    def invoke(self, method: str, payload: Dict) -> Dict:
        if self.mock_mode:
            return {
                "ok": True,
                "mode": "mock_deterministic",
                "provider": self.provider,
                "contract": self.name,
                "method": method,
                "tx_hash": self._deterministic_mock_tx_hash(method, payload),
                "timestamp": _now(),
            }

        body = json.dumps({
            "provider": self.provider,
            "contract": self.name,
            "method": method,
            "payload": payload,
            "timestamp": _now(),
        }, sort_keys=True, separators=(",", ":")).encode()
        req = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                raw = resp.read().decode()
                data = json.loads(raw) if raw else {}
            if not isinstance(data, dict):
                return {
                    "ok": False,
                    "mode": "remote_rpc",
                    "error_code": "REMOTE_CONTRACT_RESPONSE_INVALID",
                    "timestamp": _now(),
                }
            remote_ok = data.get("ok") is True
            tx_id = data.get("tx_hash") or data.get("transaction_id")
            if not remote_ok or not isinstance(tx_id, str) or not tx_id.strip() or len(tx_id) > 512:
                return {
                    "ok": False,
                    "mode": "remote_rpc",
                    "error_code": "REMOTE_CONTRACT_RECEIPT_UNVERIFIED",
                    "timestamp": _now(),
                }
            return {
                "ok": True,
                "mode": "remote_rpc",
                "provider": self.provider,
                "contract": self.name,
                "method": method,
                "tx_hash": tx_id.strip(),
                "timestamp": _now(),
            }
        except urllib.error.URLError:
            return {
                "ok": False,
                "mode": "remote_rpc",
                "error_code": "REMOTE_CONTRACT_UNREACHABLE",
                "timestamp": _now(),
            }
        except Exception:
            return {
                "ok": False,
                "mode": "remote_rpc",
                "error_code": "REMOTE_CONTRACT_FAILURE",
                "timestamp": _now(),
            }


class DynamicSmartContractEngine:
    def __init__(self):
        self.enabled = get_bool("SMART_CONTRACTS_ENABLED", True)
        self.mock_mode = get_bool("SMART_CONTRACTS_MOCK_MODE", True)

        self.eth_connector = ContractConnector(
            name=get_env("ETH_CONTRACT_NAME", "SmartCarInsuranceAndToll"),
            provider="ethereum",
            endpoint=get_env("ETH_RPC_ENDPOINT", "http://127.0.0.1:8545"),
            timeout_sec=get_int("SMART_CONTRACT_TIMEOUT_SEC", 4),
            mock_mode=self.mock_mode,
        )
        self.fabric_connector = ContractConnector(
            name=get_env("FABRIC_CHAINCODE_NAME", "smartcar_cc"),
            provider="hyperledger_fabric",
            endpoint=get_env("FABRIC_GATEWAY_ENDPOINT", "http://127.0.0.1:7050"),
            timeout_sec=get_int("SMART_CONTRACT_TIMEOUT_SEC", 4),
            mock_mode=self.mock_mode,
        )

        self.insurance_enabled = get_bool("INSURANCE_AUTO_SHARE_ENABLED", True)
        self.toll_enabled = get_bool("TOLL_AUTO_PAYMENT_ENABLED", True)
        self.maintenance_enabled = get_bool("MAINTENANCE_CONTRACT_ENABLED", True)
        self.biometric_safety_enabled = get_bool("BIOMETRIC_SAFETY_CONTRACT_ENABLED", True)
        self.toll_fee = get_float("TOLL_DEFAULT_FEE", 75.0)
        self.maintenance_temp_threshold = get_float("MAINTENANCE_TEMP_THRESHOLD", 100.0)
        self.biometric_hr_low = get_float("BIOMETRIC_HEART_RATE_LOW_BPM", 45.0)
        self.biometric_hr_high = get_float("BIOMETRIC_HEART_RATE_HIGH_BPM", 140.0)
        self.biometric_drowsy_threshold = get_float("BIOMETRIC_DROWSINESS_THRESHOLD", 0.80)

    def _insurance_rule(self, event_data: str) -> bool:
        ev = event_data.upper()
        return "EMERGENCY" in ev or "ANOMALY:DETECTED" in ev

    def _toll_rule(self, event_data: str) -> bool:
        ev = event_data.upper()
        return "V2I:SIGNAL" in ev and ("TOLL" in ev or "INT_" in ev)

    def _maintenance_rule(self, telemetry: Dict) -> bool:
        return float(telemetry.get("engine_temp", 0.0)) >= self.maintenance_temp_threshold

    def _biometric_safety_rule(self, telemetry: Dict) -> bool:
        hr = float(telemetry.get("driver_heart_rate_bpm", 0.0))
        drowsy = float(telemetry.get("driver_drowsiness_score", 0.0))
        driver_unwell = bool(telemetry.get("driver_unwell", False))
        hr_risk = (hr > 0.0) and (hr <= self.biometric_hr_low or hr >= self.biometric_hr_high)
        drowsy_risk = drowsy >= self.biometric_drowsy_threshold
        return hr_risk or drowsy_risk or driver_unwell

    def evaluate_and_invoke(self, *, vehicle_id: str, did: str, event_data: str, telemetry: Dict, block_hash: str) -> List[Dict]:
        if not self.enabled:
            return []

        receipts: List[Dict] = []
        base_payload = {
            "vehicle_id": vehicle_id,
            "did": did,
            "event_data": event_data,
            "telemetry": telemetry,
            "block_hash": block_hash,
            "timestamp": _now(),
        }

        if self.insurance_enabled and self._insurance_rule(event_data):
            payload = dict(base_payload)
            payload["share_scope"] = "emergency_or_anomaly"
            result = self.fabric_connector.invoke("submitInsuranceIncident", payload)
            result["contract_key"] = "insurance_auto_share"
            receipts.append(result)

        if self.toll_enabled and self._toll_rule(event_data):
            payload = dict(base_payload)
            payload["amount"] = self.toll_fee
            result = self.eth_connector.invoke("payToll", payload)
            result["contract_key"] = "toll_auto_payment"
            receipts.append(result)

        if self.maintenance_enabled and self._maintenance_rule(telemetry):
            payload = dict(base_payload)
            payload["maintenance_reason"] = "engine_temp_high"
            result = self.fabric_connector.invoke("submitMaintenanceAlert", payload)
            result["contract_key"] = "maintenance_alert"
            receipts.append(result)

        if self.biometric_safety_enabled and self._biometric_safety_rule(telemetry):
            payload = dict(base_payload)
            payload["biometric_reason"] = {
                "driver_heart_rate_bpm": telemetry.get("driver_heart_rate_bpm"),
                "driver_drowsiness_score": telemetry.get("driver_drowsiness_score"),
                "driver_unwell": telemetry.get("driver_unwell"),
            }
            result = self.fabric_connector.invoke("activateBiometricSafeMode", payload)
            result["contract_key"] = "biometric_safety_mode"
            result["action"] = "SAFE_MODE_ACTIVATE"
            receipts.append(result)

        return receipts
