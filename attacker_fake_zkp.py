# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Security benchmarking attacker script.

Attacks:
1) Sync attack: submits chain with fake ZKP proof (should be rejected)
2) V2I attack: sends fake speed-limit command with invalid ZKP
"""

import copy
import time
from datetime import datetime, timezone

from env_config import load_project_env_once
from blockchain import SmartCarBlockchain, TelemetryData
from sync_protocol import SyncServer, SyncClient
from v2x_protocol import V2XHub, V2XNode

load_project_env_once()


def run_sync_fake_zkp_attack():
    print("[ATTACK] Sync fake-ZKP attack started")
    server = SyncServer(port=9886)
    server.start()
    time.sleep(0.3)

    honest = SyncClient(port=9886, vehicle_id="HONEST_CAR")
    attacker = SyncClient(port=9886, vehicle_id="ATTACKER_CAR")
    assert honest.connect(), "honest connect failed"
    assert attacker.connect(), "attacker connect failed"

    bc = SmartCarBlockchain(
        vehicle_id="HONEST_CAR",
        password="pw",
        auth_token="token",
        chain_file="logs/attack_baseline_chain.json",
    )
    bc.authenticate("token")
    bc.start_engine()
    bc.push_telemetry(TelemetryData(speed=48.0, engine_temp=85.0, gps_lat=23.8, gps_lon=90.4), "TELEMETRY:BASELINE")
    bc.flush_edge_to_chain("EDGE:FORCE_FLUSH")

    valid_chain = bc.get_chain_json()
    valid_resp = honest.sync_chain(valid_chain)
    print(f"[ATTACK] Honest chain accepted={bool(valid_resp and valid_resp.get('payload', {}).get('accepted'))}")

    fake_chain = copy.deepcopy(valid_chain)
    if len(fake_chain) > 1:
        fake_chain[1]["zkp_proofs"]["speed_limit"]["proof_speed"]["s1"] = "0"
        fake_chain[1]["zkp_proofs"]["speed_limit"]["proof_speed"]["s2"] = "0"
    fake_resp = attacker.sync_chain(fake_chain)
    print(f"[ATTACK] Fake-ZKP chain accepted={bool(fake_resp and fake_resp.get('payload', {}).get('accepted'))}")

    honest.disconnect()
    attacker.disconnect()
    server.stop()
    print("[ATTACK] Sync fake-ZKP attack complete\n")


def run_v2i_fake_command_attack():
    print("[ATTACK] V2I fake command attack started")
    hub = V2XHub(port=9987)
    hub.start()
    time.sleep(0.2)

    attacker = V2XNode("malicious_infra_01", "infrastructure", port=9987)
    victim_listener_msgs = []
    victim = V2XNode("victim_car_test", "vehicle", port=9987, on_message=lambda m: victim_listener_msgs.append(m))

    assert attacker.connect(), "attacker infra connect failed"
    assert victim.connect(), "victim connect failed"

    payload = {
        "intersection_id": "INT_ATTACK",
        "signal_state": "RED",
        "ttl_sec": 8,
        "speed_limit_kmh": 15,
        "distance_to_signal_m": 35,
        # Deliberately invalid proof object
        "zkp_speed_limit": {
            "scheme": "COMMITMENT_KNOWLEDGE_LEQ",
            "valid": True,
            "limit": 15,
            "commit_speed": "999",
            "commit_diff": "888",
            "proof_speed": {"t": "1", "s1": "1", "s2": "1"},
            "proof_diff": {"t": "1", "s1": "1", "s2": "1"},
            "relation_blind": "1",
        }
    }
    attacker.send_v2i_signal("INT_ATTACK", "RED", ttl_sec=8, extra_payload=payload)
    time.sleep(0.5)

    print(f"[ATTACK] Fake V2I command sent. Victim received_messages={len(victim_listener_msgs)}")

    attacker.disconnect()
    victim.disconnect()
    hub.stop()
    print("[ATTACK] V2I fake command attack complete\n")


def main():
    print("Security Benchmark Attacker Script")
    print(f"UTC: {datetime.now(timezone.utc).isoformat()}")
    run_sync_fake_zkp_attack()
    run_v2i_fake_command_attack()
    print("Done.")


if __name__ == "__main__":
    main()

