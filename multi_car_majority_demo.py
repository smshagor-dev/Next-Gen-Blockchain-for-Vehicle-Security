# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Multi-car majority vote demo using sync_protocol.py.

Shows 3 car nodes verifying a proposed block and submitting votes.
Consensus is accepted on majority YES vote.
"""

import time
import hashlib
from datetime import datetime, timezone

from env_config import load_project_env_once
from sync_protocol import SyncServer, SyncClient

load_project_env_once()


def sha3_256(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()


def compute_block_hash(index: int, timestamp: str, vehicle_id: str,
                       telemetry_hash_sha3: str, event_hash_sha3: str,
                       previous_hash: str) -> str:
    raw = f"{index}{timestamp}{vehicle_id}{telemetry_hash_sha3}{event_hash_sha3}{previous_hash}"
    return sha3_256(raw)


def make_candidate_block(previous_hash: str, tamper: bool = False) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    tel_hash = sha3_256("speed=72.2,temp=87.3,obstacle=120.0")
    evt_hash = sha3_256("V2V:MERGE_WARNING")
    block_hash = compute_block_hash(1, ts, "FLEET_SHARED_LEDGER", tel_hash, evt_hash, previous_hash)
    if tamper:
        block_hash = "deadbeef" + block_hash[8:]
    return {
        "index": 1,
        "timestamp": ts,
        "vehicle_id": "FLEET_SHARED_LEDGER",
        "telemetry_hash_sha3": tel_hash,
        "event_hash_sha3": evt_hash,
        "previous_hash": previous_hash,
        "block_hash": block_hash,
    }


def verify_candidate_locally(block: dict, expected_previous_hash: str) -> (bool, str):
    if block.get("previous_hash") != expected_previous_hash:
        return False, "previous_hash_mismatch"
    expected = compute_block_hash(
        int(block["index"]),
        str(block["timestamp"]),
        str(block["vehicle_id"]),
        str(block["telemetry_hash_sha3"]),
        str(block["event_hash_sha3"]),
        str(block["previous_hash"]),
    )
    if expected != block.get("block_hash"):
        return False, "block_hash_invalid"
    return True, "ok"


def main():
    print("Starting majority-vote multi-car demo...")
    server = SyncServer()
    server.start()
    time.sleep(0.4)

    car_ids = ["CAR_A_001", "CAR_B_002", "CAR_C_003"]
    clients = []
    for cid in car_ids:
        c = SyncClient(vehicle_id=cid)
        if not c.connect():
            print(f"{cid}: connect failed")
            continue
        clients.append((cid, c))
        print(f"{cid}: connected")

    if len(clients) < 2:
        print("Need at least 2 connected car nodes for majority demo.")
        server.stop()
        return

    shared_prev_hash = "0" * 64

    # Round 1: Valid proposal (expected majority YES)
    proposal_id_ok = "proposal_valid_001"
    candidate_ok = make_candidate_block(shared_prev_hash, tamper=False)
    print(f"\n[Round 1] Proposal {proposal_id_ok} (valid block)")
    for cid, client in clients:
        vote, reason = verify_candidate_locally(candidate_ok, shared_prev_hash)
        resp = client.submit_vote(proposal_id_ok, cid, vote, reason)
        print(f"{cid} vote={vote} reason={reason} ack={bool(resp)}")

    tally_ok = clients[0][1].request_vote_tally(proposal_id_ok)
    print(f"Tally: YES={tally_ok['payload']['yes_votes']} NO={tally_ok['payload']['no_votes']} "
          f"TOTAL={tally_ok['payload']['total_votes']} "
          f"MAJORITY_ACCEPT={tally_ok['payload']['majority_accept']}")

    # Round 2: Tampered proposal (expected majority NO)
    proposal_id_bad = "proposal_tampered_002"
    candidate_bad = make_candidate_block(shared_prev_hash, tamper=True)
    print(f"\n[Round 2] Proposal {proposal_id_bad} (tampered block)")
    for cid, client in clients:
        vote, reason = verify_candidate_locally(candidate_bad, shared_prev_hash)
        resp = client.submit_vote(proposal_id_bad, cid, vote, reason)
        print(f"{cid} vote={vote} reason={reason} ack={bool(resp)}")

    tally_bad = clients[0][1].request_vote_tally(proposal_id_bad)
    print(f"Tally: YES={tally_bad['payload']['yes_votes']} NO={tally_bad['payload']['no_votes']} "
          f"TOTAL={tally_bad['payload']['total_votes']} "
          f"MAJORITY_ACCEPT={tally_bad['payload']['majority_accept']}")

    for _, c in clients:
        c.disconnect()
    server.stop()
    print("\nDemo complete.")


if __name__ == "__main__":
    main()

