# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Network overhead analysis for SmartCar sync protocol.

Compares byte cost of:
1) Plain JSON payload
2) Protocol envelope (no MAC)
3) Protocol + HMAC (hashed/authenticated)
4) Encrypted payload + HMAC

Outputs:
- logs/network_overhead_report.json
- logs/network_overhead_report.csv
- logs/network_overhead_chart.png
"""

import csv
import json
import os
from datetime import datetime, timezone

from env_config import load_project_env_once, get_env
from sync_protocol import create_message, MessageType
from blockchain import SmartCarCrypto

load_project_env_once()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _bytes_len(data) -> int:
    if isinstance(data, bytes):
        return len(data)
    if isinstance(data, str):
        return len(data.encode())
    return len(json.dumps(data, separators=(",", ":")).encode())


def _sample_payloads():
    small = {
        "vehicle_id": "CAR_A_001",
        "speed": 52.4,
        "rpm": 2680,
        "obstacle_distance": 130.0,
    }
    medium = {
        "vehicle_id": "CAR_A_001",
        "telemetry": {
            "speed": 63.1, "acceleration": 1.4, "fuel_level": 82.3, "battery_voltage": 13.7,
            "engine_temp": 88.5, "gps_lat": 23.81035, "gps_lon": 90.41251, "obstacle_distance": 95.0,
            "emergency_brake_active": True, "steering_angle": -3.4, "brake_pressure": 25.0,
            "throttle_position": 42.1, "rpm": 3120.0, "odometer": 12054.22, "timestamp": _now()
        },
        "event": "V2I:SIGNAL:INT_01:YELLOW:TTL_8:LIMIT_50",
        "did": "did:smartcar:abc123",
    }
    large = {
        "vehicle_id": "CAR_A_001",
        "chain_fragment": [
            {
                "index": i,
                "timestamp": _now(),
                "event_data": f"TELEMETRY:WINDOW_{i}",
                "telemetry_hash_sha3": "a" * 64,
                "event_hash_sha3": "b" * 64,
                "block_hash": "c" * 64,
                "previous_hash": "d" * 64,
            }
            for i in range(8)
        ],
        "meta": {"sync_type": "BLOCK_BATCH", "count": 8}
    }
    return [("small", small), ("medium", medium), ("large", large)]


def analyze():
    session_key = get_env("SMARTCAR_SYNC_SHARED_KEY", "SmartCarNetworkKey2024")
    crypto_password = get_env("SMARTCAR_PASSWORD", "SmartCarSecretKey2024!@#")
    crypto = SmartCarCrypto(crypto_password)

    rows = []

    for label, payload in _sample_payloads():
        plain_payload_bytes = _bytes_len(payload)

        protocol_no_mac = create_message(MessageType.SYNC_REQUEST, payload, session_key="")
        protocol_no_mac_bytes = _bytes_len(protocol_no_mac)

        protocol_hmac = create_message(MessageType.SYNC_REQUEST, payload, session_key=session_key)
        protocol_hmac_bytes = _bytes_len(protocol_hmac)

        encrypted_payload = crypto.encrypt(json.dumps(payload, separators=(",", ":")))
        enc_obj = {
            "vehicle_id": payload.get("vehicle_id", "CAR"),
            "ciphertext": encrypted_payload,
            "encoding": "base64",
            "cipher": "PBKDF2_XOR_HMAC",
        }
        encrypted_hmac = create_message(MessageType.SYNC_REQUEST, enc_obj, session_key=session_key)
        encrypted_hmac_bytes = _bytes_len(encrypted_hmac)

        row = {
            "sample": label,
            "plain_json_bytes": plain_payload_bytes,
            "protocol_no_mac_bytes": protocol_no_mac_bytes,
            "protocol_hmac_bytes": protocol_hmac_bytes,
            "encrypted_hmac_bytes": encrypted_hmac_bytes,
            "overhead_protocol_no_mac_pct": round((protocol_no_mac_bytes - plain_payload_bytes) * 100 / plain_payload_bytes, 2),
            "overhead_protocol_hmac_pct": round((protocol_hmac_bytes - plain_payload_bytes) * 100 / plain_payload_bytes, 2),
            "overhead_encrypted_hmac_pct": round((encrypted_hmac_bytes - plain_payload_bytes) * 100 / plain_payload_bytes, 2),
        }
        rows.append(row)

    return rows


def save_outputs(rows):
    os.makedirs("logs", exist_ok=True)
    json_path = "logs/network_overhead_report.json"
    csv_path = "logs/network_overhead_report.csv"
    png_path = "logs/network_overhead_chart.png"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": _now(),
            "rows": rows
        }, f, indent=2)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # Chart generation
    try:
        import matplotlib.pyplot as plt
        import numpy as np

        labels = [r["sample"] for r in rows]
        plain = [r["plain_json_bytes"] for r in rows]
        no_mac = [r["protocol_no_mac_bytes"] for r in rows]
        hmac = [r["protocol_hmac_bytes"] for r in rows]
        enc = [r["encrypted_hmac_bytes"] for r in rows]

        x = np.arange(len(labels))
        width = 0.2

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.bar(x - 1.5 * width, plain, width, label="Plain JSON")
        ax.bar(x - 0.5 * width, no_mac, width, label="Protocol (no MAC)")
        ax.bar(x + 0.5 * width, hmac, width, label="Protocol + HMAC")
        ax.bar(x + 1.5 * width, enc, width, label="Encrypted + HMAC")

        ax.set_title("SmartCar Sync Network Overhead (Bytes)")
        ax.set_xlabel("Payload Size")
        ax.set_ylabel("Bytes Transferred")
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.legend()
        ax.grid(axis="y", linestyle="--", alpha=0.35)

        plt.tight_layout()
        plt.savefig(png_path, dpi=150)
        plt.close(fig)
        chart_status = "ok"
    except Exception as e:
        chart_status = f"failed: {e}"

    return json_path, csv_path, png_path, chart_status


def main():
    rows = analyze()
    json_path, csv_path, png_path, chart_status = save_outputs(rows)
    print("Network Overhead Analysis Complete")
    print(f"- JSON report: {json_path}")
    print(f"- CSV report : {csv_path}")
    print(f"- Chart PNG  : {png_path} ({chart_status})")
    for r in rows:
        print(
            f"[{r['sample']}] plain={r['plain_json_bytes']} "
            f"proto_no_mac={r['protocol_no_mac_bytes']} "
            f"proto_hmac={r['protocol_hmac_bytes']} "
            f"enc_hmac={r['encrypted_hmac_bytes']}"
        )


if __name__ == "__main__":
    main()

