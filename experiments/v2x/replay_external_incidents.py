"""Label-isolated replay of a fixed external V2X event trace against real gates.

The trace NEVER contains ground truth. Independently supplied world truth
is joined only after all policy decisions. Session-verified flags here are
capture-adapter assertions, NOT independently checked session MACs.

This harness is a software experiment *protocol*, not publishable field data.
It performs no CAN/ECU action and cannot infer physical sensor provenance.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
import hashlib
import hmac
import io
import json
import math
from pathlib import Path
import time

from attested_interval_join import utc
from join_world_incidents import WORLD_COLUMNS, digest, rows_from_bytes
from v2x_evidence_admission import (
    AUTH_ID_RE, EvidenceAdmissionGate, parse_evidence,
)

EVENT_COLUMNS = (
    "experiment_id", "scenario_id", "seed", "split", "seq", "received_at",
    "session_verified", "node_id", "nonce", "incident_id", "event_class",
    "observed_at", "lat", "lon", "sensor_sha256",
)
GROUP_COLUMNS = ("experiment_id", "scenario_id", "seed", "split")
METHODS = ("authenticated_only", "evidence_quorum_2", "ablation_quorum_3",
           "ablation_radius_10km")
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_INPUT_EVENTS = 100000


def read_events(raw: bytes, group: tuple[str, ...],
                start: datetime, end: datetime) -> list[dict]:
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
        raise ValueError("event trace exceeds bounded input size")
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("invalid trace encoding") from exc
    reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
    if reader.fieldnames != list(EVENT_COLUMNS):
        raise ValueError("event schema must match label-free columns exactly")
    rows = []
    previous_time = None
    previous_seq = -1
    for row in reader:
        if len(rows) >= MAX_INPUT_EVENTS:
            raise ValueError("event trace exceeds bounded event count")
        if None in row or any(not isinstance(row[k], str) or not row[k]
                             for k in EVENT_COLUMNS):
            raise ValueError("missing or malformed event fields")
        if tuple(row[k] for k in GROUP_COLUMNS) != group:
            raise ValueError("mixed scenario, seed or split in event trace")
        try:
            sequence = int(row["seq"])
            when = utc(row["received_at"])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid event sequence or timestamp") from exc
        if row["seq"] != str(sequence) or sequence <= previous_seq or sequence < 0:
            raise ValueError("duplicate or non-increasing event sequence")
        if when < start or when >= end:
            raise ValueError("event timestamp outside experiment window")
        if previous_time is not None and when < previous_time:
            raise ValueError("nonchronological events")
        if row["session_verified"] not in ("0", "1"):
            raise ValueError("invalid asserted session boolean")
        previous_seq, previous_time = sequence, when
        rows.append({**row, "_when": when, "_seq": sequence})
    return rows


def replay(world_bytes: bytes, events_bytes: bytes, *,
           pinned_world_sha256: str, pinned_events_sha256: str,
           expected_group: tuple[str, str, str, str],
           window_start: str, window_end: str,
           max_incidents: int = 512) -> dict:
    if not isinstance(expected_group, tuple) or len(expected_group) != 4 or not all(
            isinstance(x, str) and x for x in expected_group):
        raise ValueError("invalid selected experiment group")
    if any(not isinstance(x, str) for x in (pinned_world_sha256, pinned_events_sha256)):
        raise ValueError("invalid external source pins")
    if not hmac.compare_digest(digest(world_bytes), pinned_world_sha256) or not hmac.compare_digest(
            digest(events_bytes), pinned_events_sha256):
        raise ValueError("operator-pinned source SHA-256 mismatch")
    if type(max_incidents) is not int or not 1 <= max_incidents <= 100000:
        raise ValueError("invalid bounded incident capacity")
    start, end = utc(window_start), utc(window_end)
    if end <= start:
        raise ValueError("invalid observation window")
    world = rows_from_bytes(world_bytes, WORLD_COLUMNS)
    truth: dict[str, bool] = {}
    for row in world:
        if tuple(row[k] for k in GROUP_COLUMNS) != expected_group:
            raise ValueError("independent world scenario/split mismatch")
        if row["ground_truth"] not in ("0", "1"):
            raise ValueError("world ground truth must be binary")
        incident = row["incident_id"]
        if incident in truth:
            raise ValueError("duplicate world incident")
        truth[incident] = row["ground_truth"] == "1"
    rows = read_events(events_bytes, expected_group, start, end)
    if any(row["incident_id"] not in truth for row in rows):
        raise ValueError("event references incident absent from independent world")
    now_state = {"utc": start, "monotonic": 0.0}
    def clock():
        return now_state["monotonic"]
    def utc_clock():
        return now_state["utc"]
    gates = {
        "evidence_quorum_2": EvidenceAdmissionGate(
            quorum=2, max_incidents=max_incidents, clock=clock, utc_clock=utc_clock),
        "ablation_quorum_3": EvidenceAdmissionGate(
            quorum=3, max_incidents=max_incidents, clock=clock, utc_clock=utc_clock),
        "ablation_radius_10km": EvidenceAdmissionGate(
            quorum=2, max_distance_m=10000, max_incidents=max_incidents,
            clock=clock, utc_clock=utc_clock),
    }
    first_valid_received: dict[str, float] = {}
    relayed: dict[str, dict[str, float]] = {method: {} for method in METHODS}
    seen_nonces: set[tuple[str, str]] = set()
    counters = {"events": 0, "asserted_unverified": 0,
                "replayed_nonce_rejected": 0, "invalid_evidence_rejected": 0}
    decisions = []
    max_pending = {name: 0 for name in gates}
    wall0, cpu0 = time.perf_counter_ns(), time.process_time_ns()
    for row in rows:
        counters["events"] += 1
        incident = row["incident_id"]
        when = row["_when"]
        now_state["utc"] = when
        now_state["monotonic"] = (when - start).total_seconds()
        rel_ms = now_state["monotonic"] * 1000
        statuses = {"seq": row["_seq"], "incident_id": incident}
        if row["session_verified"] != "1":
            counters["asserted_unverified"] += 1
            reason = "rejected_unverified_session_claim"
        elif not AUTH_ID_RE.fullmatch(row["node_id"]):
            reason = "rejected_invalid_authenticated_sender_id"
            counters["invalid_evidence_rejected"] += 1
        elif (row["node_id"], row["nonce"]) in seen_nonces:
            counters["replayed_nonce_rejected"] += 1
            reason = "rejected_replayed_nonce"
        else:
            seen_nonces.add((row["node_id"], row["nonce"]))
            try:
                payload = {"evidence": {
                    "incident_id": incident,
                    "event_class": row["event_class"],
                    "observed_at": row["observed_at"],
                    "lat": float(row["lat"]), "lon": float(row["lon"]),
                    "sensor_sha256": row["sensor_sha256"],
                }}
                parse_evidence(payload, now=when, max_age_sec=15)
            except (ValueError, OverflowError, TypeError):
                counters["invalid_evidence_rejected"] += 1
                reason = "rejected_invalid_evidence"
            else:
                reason = ""
                first_valid_received.setdefault(incident, rel_ms)
                relayed["authenticated_only"].setdefault(incident, rel_ms)
                statuses["authenticated_only"] = "relayed"
                for name, gate in gates.items():
                    outcome = gate.evaluate(
                        authenticated_sender_id=row["node_id"], payload=payload)
                    statuses[name] = outcome.status + ":" + outcome.reason
                    if outcome.relayed:
                        relayed[name].setdefault(incident, rel_ms)
                    max_pending[name] = max(max_pending[name], gate.snapshot()["active_incidents"])
        if reason:
            for method in METHODS:
                statuses[method] = reason
        decisions.append(statuses)
    measured_wall_ms = (time.perf_counter_ns() - wall0) / 1e6
    measured_cpu_ms = (time.process_time_ns() - cpu0) / 1e6

    results = {}
    for method in METHODS:
        tp = fp = fn = tn = 0
        delays = []
        for incident, positive in truth.items():
            predicted = incident in relayed[method]
            if positive and predicted:
                tp += 1
                delays.append(relayed[method][incident] - first_valid_received[incident])
            elif positive:
                fn += 1
            elif predicted:
                fp += 1
            else:
                tn += 1
        results[method] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "accuracy": (tp + tn) / len(truth),
            "delay_from_first_valid_received_ms": {
                "observations": len(delays),
                "mean": sum(delays) / len(delays) if delays else None,
                "max": max(delays) if delays else None,
            },
            "relayed_incidents": sorted(relayed[method]),
        }
    return {
        "status": "label_isolated_offline_policy_replay",
        "publication_ready": False,
        "source_sha256": {"world": digest(world_bytes), "events": digest(events_bytes)},
        "experiment_id": expected_group[0], "scenario_id": expected_group[1],
        "seed": expected_group[2], "split": expected_group[3],
        "window_start": window_start, "window_end": window_end,
        "independent_world_incidents": len(truth),
        "event_admission_counters": counters,
        "methods": results,
        "decisions": decisions,
        "resource_observations": {
            "replay_wall_ms": measured_wall_ms,
            "replay_cpu_ms": measured_cpu_ms,
            "maximum_active_incident_states": max_pending,
            "note": "Local Python replay, not network end-to-end latency or physical throughput.",
        },
        "limitations": [
            "session_verified is a trace adapter claim; no live session MAC or signed hardware sender was verified.",
            "World truth is external and separate from policy inputs, but annotator independence is unverified.",
            "All variants run on one identical observed event stream, not separately instrumented physical trials.",
            "Absent world hazards count as false negatives; no-event capture does not establish real sensor uptime.",
            "Multiple enrolled identities can collude; evidence hashes are not independent sensor attestations.",
            "Local CPU/wall measurements are not independent statistical replication or deployable benchmark evidence.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Label-isolated external V2X policy replay; experimental protocol only")
    p.add_argument("--world", required=True, type=Path)
    p.add_argument("--events", required=True, type=Path)
    p.add_argument("--world-sha256", required=True)
    p.add_argument("--events-sha256", required=True)
    for name in GROUP_COLUMNS:
        p.add_argument("--" + name.replace("_", "-"), required=True)
    p.add_argument("--window-start", required=True)
    p.add_argument("--window-end", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-incidents", type=int, default=512)
    a = p.parse_args()
    raw_world, raw_events = a.world.read_bytes(), a.events.read_bytes()
    report = replay(
        raw_world, raw_events, pinned_world_sha256=a.world_sha256,
        pinned_events_sha256=a.events_sha256,
        expected_group=tuple(getattr(a, name) for name in GROUP_COLUMNS),
        window_start=a.window_start, window_end=a.window_end,
        max_incidents=a.max_incidents)
    payload = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
    a.output.write_text(payload, encoding="utf-8")
    print(json.dumps({"result_sha256": digest(payload.encode()),
                      "publication_ready": False, "world_incidents": report["independent_world_incidents"]}))


if __name__ == "__main__":
    main()
