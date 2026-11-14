"""Fail-closed offline join of independently labeled incident opportunities and hub captures.

HMAC authenticates *export integrity only*: it does not prove sensor observations,
session authentication, annotator trust, or real-world ground truth.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
from pathlib import Path

WORLD_COLUMNS = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "ground_truth")
CAPTURE_COLUMNS = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "node_id", "nonce", "received_at", "session_verified", "alert_relayed")
FORBIDDEN = {"attacker", "ground_truth_incident", "label", "is_attacker"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rows_from_bytes(data: bytes, columns: tuple[str, ...], *, allow_empty: bool = False) -> list[dict[str, str]]:
    text = data.decode("utf-8-sig")
    import io
    reader = csv.DictReader(io.StringIO(text), strict=True)
    headers = reader.fieldnames or []
    if len(headers) != len(set(headers)) or set(headers) != set(columns):
        raise ValueError("unexpected, duplicated or missing columns")
    rows = list(reader)
    if (not rows and not allow_empty) or any(None in row or any(not row[k] for k in columns) for row in rows):
        raise ValueError("empty or malformed rows")
    return rows


def verify_receipt(capture: bytes, receipt: dict, key: bytes) -> None:
    if not key or set(receipt) != {"capture_sha256", "hmac_sha256"}:
        raise ValueError("invalid export receipt")
    if not hmac.compare_digest(receipt["capture_sha256"], digest(capture)):
        raise ValueError("capture digest mismatch")
    expected = hmac.new(key, capture, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, receipt["hmac_sha256"]):
        raise ValueError("hub export HMAC mismatch")


def evaluate(world_bytes: bytes, capture_bytes: bytes, receipt: dict,
             key: bytes, pinned_world_sha256: str, pinned_capture_sha256: str) -> dict:
    if digest(world_bytes) != pinned_world_sha256 or digest(capture_bytes) != pinned_capture_sha256:
        raise ValueError("operator-pinned source digest mismatch")
    verify_receipt(capture_bytes, receipt, key)
    world = rows_from_bytes(world_bytes, WORLD_COLUMNS)
    captures = rows_from_bytes(capture_bytes, CAPTURE_COLUMNS, allow_empty=True)
    universe = {}
    groups = set()
    for row in world:
        if row["ground_truth"] not in ("0", "1"):
            raise ValueError("invalid world label")
        group = tuple(row[k] for k in WORLD_COLUMNS[:4])
        groups.add(group)
        identity = (*group, row["incident_id"])
        if identity in universe:
            raise ValueError("duplicate world incident")
        universe[identity] = row["ground_truth"] == "1"
    if len(groups) != 1:
        raise ValueError("mixed world scenario/seed/split")
    seen_nonces = set()
    accepted = set()
    trace = []
    for row in captures:
        group = tuple(row[k] for k in CAPTURE_COLUMNS[:4])
        identity = (*group, row["incident_id"])
        if group not in groups or identity not in universe:
            raise ValueError("capture without matching independent world label")
        if row["session_verified"] not in ("0", "1") or row["alert_relayed"] not in ("0", "1"):
            raise ValueError("invalid capture boolean")
        if row["alert_relayed"] == "1" and row["session_verified"] != "1":
            raise ValueError("unverified relay")
        nonce = (group, row["node_id"], row["nonce"])
        if nonce in seen_nonces:
            raise ValueError("replayed hub export nonce")
        seen_nonces.add(nonce)
        from datetime import datetime
        try:
            timestamp = datetime.fromisoformat(row["received_at"].replace("Z", "+00:00"))
            if timestamp.utcoffset() is None:
                raise ValueError("timezone required")
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid timestamp") from exc
        if row["alert_relayed"] == "1":
            accepted.add(identity)
        trace.append({"incident_id": row["incident_id"], "node_id": row["node_id"],
                      "nonce": row["nonce"], "alert_relayed": row["alert_relayed"] == "1"})
    tp = sum(label and identity in accepted for identity, label in universe.items())
    fn = sum(label and identity not in accepted for identity, label in universe.items())
    fp = sum(not label and identity in accepted for identity, label in universe.items())
    tn = sum(not label and identity not in accepted for identity, label in universe.items())
    return {"publication_ready": False, "status": "source_join_integrity_only",
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "unobserved_positive_incidents": sum(label and identity not in {
                (*tuple(row[k] for k in CAPTURE_COLUMNS[:4]), row["incident_id"])
                for row in captures} for identity, label in universe.items()),
            "world_incidents": len(universe), "capture_rows": len(captures),
            "world_sha256": digest(world_bytes), "capture_sha256": digest(capture_bytes),
            "decision_trace": trace,
            "limitations": ["HMAC proves hub export integrity only; no session MAC, annotator trust, or sensor attestation.",
                            "World labels and hub exports must originate from independently controlled trusted sources.",
                            "An empty but authenticated capture is counted as zero relays, not silently dropped from availability evaluation.",
                            "This adapter does not evaluate V2X admission policy or constitute publishable experiments."]}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--world", type=Path, required=True)
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--key-file", type=Path, required=True)
    p.add_argument("--world-sha256", required=True)
    p.add_argument("--capture-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = evaluate(a.world.read_bytes(), a.capture.read_bytes(),
                      json.loads(a.receipt.read_text()), a.key_file.read_bytes(),
                      a.world_sha256, a.capture_sha256)
    payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
    a.output.write_text(payload, encoding="utf-8")
    print(json.dumps({"result_sha256": digest(payload.encode()), "publication_ready": False}))


if __name__ == "__main__":
    main()
