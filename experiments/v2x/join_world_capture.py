"""Integrity-gated join of independently supplied world labels and hub exports.

This offline adapter binds a *separate world-state incident universe* to
integrity-protected hub export records before the existing V2X replay evaluator.

Security boundaries:
- Export HMAC authenticates possession of an exporter key, not original V2X
  session-MAC verification, physical sensor provenance or truthful annotations.
- The capture's session_verified field is a MAC-bound *hub exporter claim*.
- The original incident truth is supplied by a separate annotation artifact.
  A SHA-256 check verifies its bytes, NOT whether the labels are correct.
- Unreceived world-state incidents are retained as denominator opportunities.
- CAM attacker flags can never substitute for incident-level truth.

No physical actuation or production network path is modified.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from experiments.v2x.audit_incident_splits import audit as structural_incident_audit
from experiments.v2x.evaluate_admission import COLUMNS, evaluate, read_trace
from v2x_evidence_admission import parse_evidence

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
NONCE_RE = re.compile(r"^[a-f0-9]{32,64}$")
WORLD_COLUMNS = (
    "source_id", "scenario_id", "seed", "group_id", "split", "incident_id",
    "label", "label_provenance", "world_event_at",
)
CAPTURE_COLUMNS = frozenset((
    "capture_id", "source_id", "scenario_id", "seed", "seq",
    "received_at", "session_verified", "bound_sender_id", "message", "export_mac",
))
EXTRA_MESSAGE_COLUMNS = frozenset((
    "type", "sender_id", "sender_type", "timestamp", "nonce", "payload", "security",
))
MAX_WORLD_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_CAPTURE_LINE_BYTES = 65536
METHODS = (
    "authenticated_only", "evidence_quorum_2",
    "ablation_quorum_3", "ablation_wide_radius_10km",
)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _utc(raw: object, field: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError(f"{field}: timestamp must be text")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field}: invalid timestamp") from exc
    if value.tzinfo is None:
        raise ValueError(f"{field}: explicit timezone required")
    return value.astimezone(timezone.utc)


def _expected_digest(actual: str, claimed: str, what: str) -> None:
    if not isinstance(claimed, str) or not SHA256_RE.fullmatch(claimed):
        raise ValueError(f"{what}: expected SHA-256 must be pinned externally")
    if not hmac.compare_digest(actual, claimed):
        raise ValueError(f"{what}: pinned SHA-256 mismatch")


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _world_rows(path: Path, manifest: dict) -> tuple[dict[str, dict], tuple[str, str, int]]:
    if path.stat().st_size > MAX_WORLD_BYTES:
        raise ValueError("world-state CSV exceeds configured bound")
    structural_incident_audit(path)  # denies CAM attacker as ground truth and cross-split groups
    world: dict[str, dict] = {}
    scope = None
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not set(WORLD_COLUMNS).issubset(reader.fieldnames or []):
            raise ValueError("missing world-state columns")
        for line, row in enumerate(reader, 2):
            if None in row or any(not isinstance(row.get(c), str) or not row[c].strip()
                                  for c in WORLD_COLUMNS):
                raise ValueError(f"world-state row {line}: missing or malformed fields")
            try:
                seed = int(row["seed"])
            except ValueError as exc:
                raise ValueError("invalid world-state seed") from exc
            if seed < 0 or row["split"] != "test":
                raise ValueError("world-state evaluation requires a pinned test partition")
            key = (row["source_id"], row["scenario_id"], seed)
            if scope is not None and key != scope:
                raise ValueError("world-state manifest must contain exactly one source/scenario/seed")
            scope = key
            if row["incident_id"] in world:
                raise ValueError("world-state incident IDs must be globally unique per scenario")
            world[row["incident_id"]] = {
                "label": row["label"] == "1",
                "time": _utc(row["world_event_at"], "world_event_at"),
                "group_id": row["group_id"],
                "provenance": row["label_provenance"],
            }
    if not world or scope is None:
        raise ValueError("world-state universe is empty")
    if manifest.get("source_id") != scope[0] or manifest.get("scenario_id") != scope[1]:
        raise ValueError("world metadata scope does not match annotations")
    if type(manifest.get("seed")) is not int or manifest["seed"] != scope[2]:
        raise ValueError("world metadata seed does not match annotations")
    return world, scope


def _load_manifest(path: Path, world_path: Path, capture_path: Path,
                   expected_world: str, expected_capture: str) -> dict:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid source metadata JSON") from exc
    if not isinstance(manifest, dict):
        raise ValueError("source metadata must be a JSON object")
    required = (
        "source_id", "scenario_id", "seed", "world_sha256", "capture_sha256",
        "world_source", "world_label_protocol", "world_label_reviewer",
        "hub_export_origin", "capture_verifier_version", "source_commit", "license",
    )
    if any(k not in manifest for k in required):
        raise ValueError("source metadata missing required evidence provenance")
    for key in required:
        if key != "seed" and (not isinstance(manifest[key], str) or not manifest[key].strip()):
            raise ValueError("source metadata fields must be nonempty text")
    _expected_digest(_sha(world_path), expected_world, "world CSV")
    _expected_digest(_sha(capture_path), expected_capture, "hub capture")
    _expected_digest(expected_world, manifest["world_sha256"], "world metadata")
    _expected_digest(expected_capture, manifest["capture_sha256"], "capture metadata")
    return manifest


def _read_export_key(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
        raise ValueError("hub exporter HMAC secret file missing, linked or oversized")
    info = path.stat()
    if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("hub exporter key must have private owner-only file permissions")
    value = path.read_bytes()
    if len(value) < 32:
        raise ValueError("hub exporter key must be at least 32 bytes")
    return value


def _verify_capture(path: Path, key: bytes, world: dict, scope: tuple[str, str, int]
                    ) -> tuple[list[dict], dict]:
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("capture export exceeds configured bound")
    normalized = []
    seen_capture_ids: set[str] = set()
    verified_nonces: set[tuple[str, str]] = set()
    counters = {"captured_records": 0, "receipt_hmac_verified": 0,
                "hub_claims_session_verified": 0, "hub_claims_session_rejected": 0}
    last_seq, last_time = 0, None
    with path.open("rb") as f:
        for line_number, blob in enumerate(f, 1):
            if len(blob) > MAX_CAPTURE_LINE_BYTES:
                raise ValueError("oversized captured record")
            if not blob.strip():
                raise ValueError("blank captured record")
            try:
                record = json.loads(blob)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid captured JSON at line {line_number}") from exc
            if not isinstance(record, dict) or set(record) != CAPTURE_COLUMNS:
                raise ValueError("unexpected/missing capture export fields")
            supplied_mac = record["export_mac"]
            if not isinstance(supplied_mac, str) or not SHA256_RE.fullmatch(supplied_mac):
                raise ValueError("invalid hub-export receipt HMAC")
            bare = dict(record)
            bare.pop("export_mac")
            expected = hmac.new(key, _canonical(bare), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(supplied_mac, expected):
                raise ValueError(f"hub-export receipt HMAC mismatch at line {line_number}")
            counters["receipt_hmac_verified"] += 1
            if type(record["seed"]) is not int or record["seed"] < 0:
                raise ValueError("capture seed must be a nonnegative integer, not bool")
            if (record["source_id"], record["scenario_id"], record["seed"]) != scope:
                raise ValueError("capture source/scenario/seed differs from world universe")
            if type(record["seq"]) is not int or record["seq"] <= last_seq:
                raise ValueError("capture sequence must strictly increase")
            last_seq = record["seq"]
            t = _utc(record["received_at"], "received_at")
            if last_time is not None and t < last_time:
                raise ValueError("capture receipt time must be nondecreasing")
            last_time = t
            cid = record["capture_id"]
            if not isinstance(cid, str) or not cid or cid in seen_capture_ids:
                raise ValueError("capture receipt ID is missing or repeated")
            seen_capture_ids.add(cid)
            if type(record["session_verified"]) is not bool:
                raise ValueError("hub verified-session field must be bool")
            msg = record["message"]
            if not isinstance(msg, dict) or set(msg) != EXTRA_MESSAGE_COLUMNS:
                raise ValueError("captured V2X ALERT does not match strict message shape")
            if msg["type"] != "ALERT":
                raise ValueError("capture adapter only handles ALERT packets")
            bound = record["bound_sender_id"]
            if not isinstance(bound, str) or not bound or msg["sender_id"] != bound:
                raise ValueError("sender identity not bound to export record")
            if not isinstance(msg["sender_type"], str) or not msg["sender_type"]:
                raise ValueError("missing sender type")
            nonce = msg["nonce"]
            if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
                raise ValueError("invalid V2X replay nonce")
            timestamp = _utc(msg["timestamp"], "message.timestamp")
            if abs((timestamp - t).total_seconds()) > 120:
                raise ValueError("recorded V2X timestamp outside exporter receipt bound")
            security = msg["security"]
            if record["session_verified"]:
                if (not isinstance(security, dict)
                        or any(not isinstance(security.get(k), str) or not security[k]
                               for k in ("session_id", "scheme", "signature"))):
                    raise ValueError("hub claims session verification but signed envelope is absent")
                replay_key = (bound, nonce)
                if replay_key in verified_nonces:
                    raise ValueError("duplicate hub-verified sender nonce")
                verified_nonces.add(replay_key)
                counters["hub_claims_session_verified"] += 1
            else:
                counters["hub_claims_session_rejected"] += 1

            evidence = parse_evidence(msg["payload"], now=t, max_age_sec=15)
            truth = world.get(evidence.incident_id)
            if truth is None:
                raise ValueError("captured incident has no independently supplied world entry")
            if truth["label"] and t < truth["time"]:
                raise ValueError("true event packet predates independent world event time")
            normalized.append({
                "experiment_id": scope[0], "scenario_id": scope[1], "seed": scope[2],
                "seq": record["seq"], "received_at": t.isoformat(),
                "session_verified": "1" if record["session_verified"] else "0",
                "node_id": bound, "ground_truth_incident": "1" if truth["label"] else "0",
                "incident_id": evidence.incident_id, "event_class": evidence.event_class,
                "observed_at": evidence.observed_at.isoformat(),
                "lat": evidence.lat, "lon": evidence.lon, "sensor_sha256": evidence.sensor_sha256,
            })
            counters["captured_records"] += 1
    return normalized, counters


def _world_denominator(world: dict, statuses: list[dict], rows: list[dict]) -> dict:
    by_seq = {r["seq"]: r for r in rows}
    receipt_count = {key: 0 for key in world}
    for r in rows:
        receipt_count[r["incident_id"]] += 1
    outcomes = {}
    for method in METHODS:
        first_forward: dict[str, datetime] = {}
        for decision in statuses:
            found = (decision[method] == "relayed" if method == "authenticated_only"
                     else decision[method].startswith("accepted:"))
            if not found:
                continue
            seq = decision["seq"]
            row = by_seq[seq]
            first_forward.setdefault(row["incident_id"], _utc(row["received_at"], "received_at"))
        tp = fp = tn = fn = 0
        latencies = []
        for incident_id, annotated in world.items():
            observed = incident_id in first_forward
            if annotated["label"] and observed:
                tp += 1
                latency = (first_forward[incident_id] - annotated["time"]).total_seconds() * 1000
                if latency < 0:
                    raise ValueError("forwarded positive incident before actual world time")
                latencies.append(latency)
            elif annotated["label"]:
                fn += 1
            elif observed:
                fp += 1
            else:
                tn += 1
        outcomes[method] = {
            "tp_incidents": tp, "fp_incidents": fp, "tn_incidents": tn, "fn_incidents": fn,
            "world_incident_universe": len(world),
            "unreceived_world_positive_incidents": sum(
                d["label"] and receipt_count[incident_id] == 0
                for incident_id, d in world.items()
            ),
            "unreceived_world_negative_opportunities": sum(
                not d["label"] and receipt_count[incident_id] == 0
                for incident_id, d in world.items()
            ),
            "false_acceptance_rate": fp / (fp + tn) if fp + tn else None,
            "legitimate_delivery_rate": tp / (tp + fn) if tp + fn else None,
            "mean_world_to_forward_ms": sum(latencies) / len(latencies) if latencies else None,
        }
    return outcomes


def run(world_csv: Path, capture_jsonl: Path, metadata_file: Path,
        exporter_key_file: Path, output_dir: Path, *,
        expected_world_sha256: str, expected_capture_sha256: str) -> dict[str, Any]:
    world_csv, capture_jsonl = Path(world_csv), Path(capture_jsonl)
    source = _load_manifest(metadata_file, world_csv, capture_jsonl,
                            expected_world_sha256, expected_capture_sha256)
    world, scope = _world_rows(world_csv, source)
    records, counts = _verify_capture(capture_jsonl, _read_export_key(exporter_key_file), world, scope)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = output_dir / "joined_incident_capture.csv"
    with normalized_path.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(records)
    if records:
        replay_rows = read_trace(normalized_path)
        _, statuses = evaluate(replay_rows)
    else:
        statuses = []
    results = _world_denominator(world, statuses, records)
    received_incidents = {r["incident_id"] for r in records}
    report = {
        "status": "hub_export_integrity_bound_to_independent_claimed_world_annotations",
        "publication_ready": False,
        "independent_world_truth_verified": False,
        "original_v2x_session_mac_independently_reverified": False,
        "hub_export_receipt_hmac_checked": True,
        "evidence_quality": "cryptographically_authenticated_export_key_possession_only",
        "annotation_provenance": {
            "world_source": source["world_source"],
            "world_label_protocol": source["world_label_protocol"],
            "world_label_reviewer": source["world_label_reviewer"],
            "label_review_independently_verified": False,
            "license_declared": source["license"],
        },
        "source_id": scope[0], "scenario_id": scope[1], "seed": scope[2],
        "universe": {
            "world_incidents": len(world),
            "world_positive": sum(v["label"] for v in world.values()),
            "world_negative_opportunities": sum(not v["label"] for v in world.values()),
            "zero_capture_incidents": sum(key not in received_incidents for key in world),
        },
        "capture_counts": counts,
        "methods": results,
        "limitations": [
            "The world-state manifest and reviewer identities are supplied by operators and have not been independently authenticated against the source simulator or physical world.",
            "Hub receipt HMAC verifies exporter-key possession, not the original V2X session key exchange or sender's cryptographic signature.",
            "The capture's verified_session flag is an integrity-bound exporter claim and is not independent packet authentication.",
            "The negative incident universe is predefined by annotators; it is not an exhaustive physical opportunity denominator.",
            "No genuine independently observed incident-world labels or recorded vehicle traffic are provided by this software tool.",
            "Vehicle-to-vehicle reporter collusion, partition reliability, driving safety and hardware actuation are not proven.",
        ],
    }
    report_path = output_dir / "joined_incident_world_results.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    decisions_path = output_dir / "joined_incident_policy_decisions.csv"
    with decisions_path.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=[
            "seq", "incident_id", "verified_session_from_trace", *METHODS
        ])
        writer.writeheader()
        writer.writerows(statuses)
    manifest_path = output_dir / "joined_incident_evidence_manifest.json"
    manifest_path.write_text(json.dumps({
        "world_csv_sha256": expected_world_sha256,
        "capture_jsonl_sha256": expected_capture_sha256,
        "source_metadata_sha256": _sha(Path(metadata_file)),
        "normalized_csv_sha256": _sha(normalized_path),
        "result_sha256": _sha(report_path),
        "decisions_sha256": _sha(decisions_path),
        "publication_ready": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Join independent claimed world-state events to HMAC-bound hub exports.")
    parser.add_argument("--world-csv", required=True)
    parser.add_argument("--hub-capture-jsonl", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--exporter-key-file", required=True)
    parser.add_argument("--expected-world-sha256", required=True)
    parser.add_argument("--expected-capture-sha256", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    result = run(
        Path(args.world_csv), Path(args.hub_capture_jsonl),
        Path(args.metadata), Path(args.exporter_key_file), Path(args.output_dir),
        expected_world_sha256=args.expected_world_sha256,
        expected_capture_sha256=args.expected_capture_sha256,
    )
    print(json.dumps({
        "status": result["status"],
        "world_incidents": result["universe"]["world_incidents"],
        "hub_export_hmac_verified_records": result["capture_counts"]["receipt_hmac_verified"],
        "publication_ready": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
