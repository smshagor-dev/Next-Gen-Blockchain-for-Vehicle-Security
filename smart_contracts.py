# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Dynamic smart-contract integration for SmartCar.

Supports Ethereum/Fabric style connectors via HTTP RPC-style endpoints.
Configuration is fully driven from environment variables.
"""

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


class ContractConnector:
    def __init__(self, name: str, provider: str, endpoint: str, timeout_sec: int = 4, mock_mode: bool = True):
        self.name = name
        self.provider = provider
        self.endpoint = endpoint
        self.timeout_sec = timeout_sec
        self.mock_mode = mock_mode

    def invoke(self, method: str, payload: Dict) -> Dict:
        if self.mock_mode:
            tx_hash = f"mock_{self.provider}_{self.name}_{abs(hash(json.dumps(payload, sort_keys=True))) % 10_000_000}"
            return {
                "ok": True,
                "mode": "mock",
                "provider": self.provider,
                "contract": self.name,
                "method": method,
                "tx_hash": tx_hash,
                "timestamp": _now(),
            }

        body = json.dumps({
            "provider": self.provider,
            "contract": self.name,
            "method": method,
            "payload": payload,
            "timestamp": _now(),
        }).encode()
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
            return {"ok": True, "mode": "real", "response": data, "timestamp": _now()}
        except urllib.error.URLError as e:
            return {"ok": False, "mode": "real", "error": str(e), "timestamp": _now()}
        except Exception as e:
            return {"ok": False, "mode": "real", "error": str(e), "timestamp": _now()}


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
        self.toll_fee = get_float("TOLL_DEFAULT_FEE", 75.0)
        self.maintenance_temp_threshold = get_float("MAINTENANCE_TEMP_THRESHOLD", 100.0)

    def _insurance_rule(self, event_data: str) -> bool:
        ev = event_data.upper()
        return "EMERGENCY" in ev or "ANOMALY:DETECTED" in ev

    def _toll_rule(self, event_data: str) -> bool:
        ev = event_data.upper()
        return "V2I:SIGNAL" in ev and ("TOLL" in ev or "INT_" in ev)

    def _maintenance_rule(self, telemetry: Dict) -> bool:
        return float(telemetry.get("engine_temp", 0.0)) >= self.maintenance_temp_threshold

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

        return receipts

