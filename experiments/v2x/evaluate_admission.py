"""Offline event-admission replay from externally supplied labeled V2X reports.

The input's verified_session and ground_truth columns are *claims from a
capture adapter*, not cryptographic proofs. A dataset adapter must validate
their provenance before any manuscript inference. This runner never generates
or labels data and never declares publication readiness.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from v2x_evidence_admission import EvidenceAdmissionGate, parse_evidence

COLUMNS = (
    "experiment_id", "scenario_id", "seed", "seq", "received_at",
    "session_verified", "node_id", "ground_truth_incident",
    "incident_id", "event_class", "observed_at", "lat", "lon", "sensor_sha256",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _time(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if dt.tzinfo is None:
        raise ValueError("timezone required")
    return dt.astimezone(timezone.utc)


def _bool(value: str) -> bool:
    if value not in ("0", "1"):
        raise ValueError("boolean input must be 0 or 1")
    return value == "1"


def read_trace(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        csv_rows = csv.DictReader(f)
        missing = set(COLUMNS) - set(csv_rows.fieldnames or [])
        if missing:
            raise ValueError("missing trace columns: " + ", ".join(sorted(missing)))
        rows = []
        scenario = None
        last_time = None
        last_seq = -1
        truth_by_incident = {}
        for line_number, row in enumerate(csv_rows, 2):
            if None in row or any(row.get(c) is None for c in COLUMNS):
                raise ValueError(f"malformed trace at line {line_number}")
            try:
                seed = int(row["seed"])
                seq = int(row["seq"])
                verified = _bool(row["session_verified"])
                truth = _bool(row["ground_truth_incident"])
                event_time = _time(row["received_at"])
                lat = float(row["lat"])
                lon = float(row["lon"])
            except (ValueError, OverflowError) as exc:
                raise ValueError(f"invalid trace at line {line_number}: {exc}") from exc
            if seed < 0 or seq <= last_seq or not math.isfinite(lat) or not math.isfinite(lon):
                raise ValueError(f"invalid ordering or nonfinite coordinate at line {line_number}")
            if last_time is not None and event_time < last_time:
                raise ValueError(f"nonchronological trace at line {line_number}")
            last_seq, last_time = seq, event_time
            scenario_key = (row["experiment_id"], row["scenario_id"], seed)
            if not all(scenario_key[:2]) or (scenario is not None and scenario_key != scenario):
                raise ValueError("one experiment/scenario/seed per trace file required")
            scenario = scenario_key
            incident_id = row["incident_id"]
            if incident_id in truth_by_incident and truth_by_incident[incident_id] != truth:
                raise ValueError("contradictory ground truth for one incident")
            truth_by_incident[incident_id] = truth
            payload = {"evidence": {
                "incident_id": incident_id,
                "event_class": row["event_class"],
                "observed_at": row["observed_at"],
                "lat": lat, "lon": lon,
                "sensor_sha256": row["sensor_sha256"],
            }}
            # Validate all fields, not only accepted-session input. An
            # inconsistent adapter must not silently bias comparisons.
            parse_evidence(payload, now=event_time, max_age_sec=15)
            rows.append({
                "experiment_id": scenario_key[0], "scenario_id": scenario_key[1],
                "seed": seed, "seq": seq, "received_at": event_time,
                "verified": verified, "ground_truth": truth,
                "node_id": row["node_id"], "incident_id": incident_id,
                "payload": payload,
            })
    if not rows:
        raise ValueError("empty trace")
    return rows


def _metrics(truth: dict[str, bool], relayed: dict[str, float], first_seen: dict[str, float]) -> dict:
    tp = fp = tn = fn = 0
    delays = []
    for incident_id, expected in truth.items():
        observed = incident_id in relayed
        if expected and observed:
            tp += 1
            delays.append(relayed[incident_id] - first_seen[incident_id])
        elif expected:
            fn += 1
        elif observed:
            fp += 1
        else:
            tn += 1
    return {
        "tp_incidents": tp, "fp_incidents": fp,
        "tn_incidents": tn, "fn_incidents": fn,
        "false_acceptance_rate": fp / (fp + tn) if fp + tn else None,
        "legitimate_delivery_rate": tp / (tp + fn) if tp + fn else None,
        "mean_time_to_alert_ms": sum(delays) / len(delays) if delays else None,
        "delivered_true_incidents": len(delays),
    }


def evaluate(rows: list[dict[str, Any]]) -> tuple[dict[str, dict], list[dict]]:
    now_state = {"monotonic": 0.0, "utc": rows[0]["received_at"]}
    variants = {
        "evidence_quorum_2": EvidenceAdmissionGate(
            quorum=2, clock=lambda: now_state["monotonic"], utc_clock=lambda: now_state["utc"]
        ),
        "ablation_quorum_3": EvidenceAdmissionGate(
            quorum=3, clock=lambda: now_state["monotonic"], utc_clock=lambda: now_state["utc"]
        ),
        "ablation_wide_radius_10km": EvidenceAdmissionGate(
            quorum=2, max_distance_m=10000,
            clock=lambda: now_state["monotonic"], utc_clock=lambda: now_state["utc"]
        ),
    }
    methods = ("authenticated_only", *variants)
    relayed = {method: {} for method in methods}
    incident_truth = {}
    first_seen = {}
    decisions = []
    origin = rows[0]["received_at"]
    for row in rows:
        when = (row["received_at"] - origin).total_seconds()
        now_state.update(monotonic=when, utc=row["received_at"])
        incident_id = row["incident_id"]
        incident_truth[incident_id] = row["ground_truth"]
        first_seen.setdefault(incident_id, when * 1000)
        result = {"seq": row["seq"], "incident_id": incident_id, "verified_session_from_trace": row["verified"]}
        accepted_by_auth = row["verified"]
        if accepted_by_auth:
            relayed["authenticated_only"].setdefault(incident_id, when * 1000)
        result["authenticated_only"] = "relayed" if accepted_by_auth else "rejected_unverified"
        for name, gate in variants.items():
            if not row["verified"]:
                result[name] = "rejected_unverified"
                continue
            decision = gate.evaluate(
                authenticated_sender_id=row["node_id"], payload=row["payload"]
            )
            result[name] = decision.status + ":" + decision.reason
            if decision.relayed:
                relayed[name].setdefault(incident_id, when * 1000)
        decisions.append(result)
    return {name: _metrics(incident_truth, relayed[name], first_seen) for name in methods}, decisions


def run(input_csv: Path, output_dir: Path, *, provenance_manifest: Path | None = None) -> dict:
    input_csv = Path(input_csv)
    raw_hash = _sha256(input_csv)
    if provenance_manifest is not None:
        manifest = json.loads(Path(provenance_manifest).read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("raw_csv_sha256") != raw_hash:
            raise ValueError("source manifest hash mismatch")
        for field in ("dataset_source", "license", "split_protocol", "capture_protocol", "source_commit"):
            if not isinstance(manifest.get(field), str) or not manifest[field].strip():
                raise ValueError(f"source manifest missing {field}")
    rows = read_trace(input_csv)
    metrics, decisions = evaluate(rows)
    report = {
        "status": "offline_replay_adapter_not_cryptographically_reverified",
        "publication_ready": False,
        "provenance": "self_reported_hash_checked" if provenance_manifest else "missing",
        "input_sha256": raw_hash,
        "experiment_id": rows[0]["experiment_id"],
        "scenario_id": rows[0]["scenario_id"],
        "seed": rows[0]["seed"],
        "event_count": len(rows),
        "incident_count": len({r["incident_id"] for r in rows}),
        "methods": metrics,
        "limitations": [
            "The session_verified and ground_truth fields are supplied by an external trace adapter, not independently authenticated by this runner.",
            "First verified relays per incident define incident-level acceptance; message-level dropped corroboration is not misreported as an incident-level false negative.",
            "No real vehicle or dataset evidence is generated by this code.",
            "Enrolled identities may collude; evidence hashes do not attest physical sensor origin.",
        ],
    }
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "report": output_dir / "admission_replay.json",
        "decisions": output_dir / "admission_decisions.csv",
        "manifest": output_dir / "admission_manifest.json",
    }
    paths["report"].write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    with paths["decisions"].open("w", newline="", encoding="utf-8") as target:
        columns = ["seq", "incident_id", "verified_session_from_trace", *metrics]
        writer = csv.DictWriter(target, fieldnames=columns)
        writer.writeheader()
        writer.writerows(decisions)
    manifest = {
        "input_sha256": raw_hash,
        "report_sha256": _sha256(paths["report"]),
        "decisions_sha256": _sha256(paths["decisions"]),
        "publication_ready": False,
    }
    paths["manifest"].write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate externally captured V2X incident reports; exploratory only.")
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--provenance-manifest")
    args = parser.parse_args(argv)
    result = run(
        Path(args.input_csv), Path(args.output_dir),
        provenance_manifest=Path(args.provenance_manifest) if args.provenance_manifest else None,
    )
    print(json.dumps({
        "status": result["status"], "incidents": result["incident_count"],
        "publication_ready": False
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
