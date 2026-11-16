"""Matched, held-out V2X capture comparison; no physical control interfaces.

This adapter joins an independently defined *complete incident universe* to two
HMAC-bound hub exports over the same pre-pinned window. It never infers truth
from received packets. Capture 'complete' is only the hub's signed assertion,
not proof of sensor uptime or independent observation. Research software only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

from attested_interval_join import evaluate_interval
from join_world_incidents import CAPTURE_COLUMNS, WORLD_COLUMNS, rows_from_bytes

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_WORLD_INCIDENTS = 100_000
HEX = set("0123456789abcdef")
GROUP_FIELDS = ("experiment_id", "scenario_id", "seed", "split")
WINDOW_FIELDS = set(GROUP_FIELDS) | {"window_start", "window_end"}
PAIR_COLUMNS = ("incident_id", "cluster_id", "truth", "baseline", "candidate")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw: bytes) -> object:
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ValueError("input artifact exceeds bound")

    def no_duplicate_keys(pairs):
        data = {}
        for key, value in pairs:
            if key in data:
                raise ValueError("duplicate JSON key")
            data[key] = value
        return data

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid UTF-8/JSON artifact") from exc


def check_pin(raw: bytes, expected: str, name: str) -> None:
    if (type(expected) is not str or len(expected) != 64 or
            any(char not in HEX for char in expected) or sha256(raw) != expected):
        raise ValueError(name + " SHA-256 pin mismatch")


def _trial_identity(window: dict, incident: str | None = None) -> str:
    parts = [window[key] for key in GROUP_FIELDS[:3]]
    if incident is not None:
        parts.append(incident)
    return sha256(json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def _predictions(capture: bytes, all_incidents: set[str]) -> tuple[dict[str, int], int]:
    rows = rows_from_bytes(capture, CAPTURE_COLUMNS, allow_empty=True)
    if len(rows) > MAX_WORLD_INCIDENTS:
        raise ValueError("capture exceeds bounded row count")
    predicted = {incident: 0 for incident in all_incidents}
    seen = set()
    for row in rows:
        incident = row["incident_id"]
        if incident not in all_incidents:
            raise ValueError("capture incident missing from world universe")
        seen.add(incident)
        # evaluate_interval has already verified session/relay semantics, nonce
        # uniqueness, and signed interval bounds before this function is called.
        if row["alert_relayed"] == "1":
            predicted[incident] = 1
    return predicted, len(all_incidents - seen)


def compare(world: bytes, baseline_capture: bytes, candidate_capture: bytes,
            baseline_export_receipt: bytes, candidate_export_receipt: bytes,
            baseline_interval_receipt: bytes, candidate_interval_receipt: bytes,
            baseline_export_key: bytes, candidate_export_key: bytes,
            baseline_interval_key: bytes, candidate_interval_key: bytes,
            expected_window_raw: bytes, *, world_pin: str,
            baseline_pin: str, candidate_pin: str, window_pin: str) -> tuple[dict, bytes]:
    """Return conservative summary and a cluster-aware paired CSV.

    Four external SHA-256 pins should be archived before trial execution. Hashes
    only bind bytes; they do not prove when a pin was generated or who signed it.
    """
    artifacts = (world, baseline_capture, candidate_capture,
                 baseline_export_receipt, candidate_export_receipt,
                 baseline_interval_receipt, candidate_interval_receipt,
                 expected_window_raw)
    if any(type(raw) is not bytes or len(raw) > MAX_ARTIFACT_BYTES for raw in artifacts):
        raise ValueError("invalid or oversized trial artifact")
    for key in (baseline_export_key, candidate_export_key,
                baseline_interval_key, candidate_interval_key):
        if type(key) is not bytes or not key:
            raise ValueError("missing HMAC verification secret")
    for name, raw, pin in (("world", world, world_pin),
                           ("baseline", baseline_capture, baseline_pin),
                           ("candidate", candidate_capture, candidate_pin),
                           ("expected window", expected_window_raw, window_pin)):
        check_pin(raw, pin, name)
    window = strict_json(expected_window_raw)
    if (type(window) is not dict or set(window) != WINDOW_FIELDS or
            any(type(window[key]) is not str or not window[key] or len(window[key]) > 128
                for key in GROUP_FIELDS) or window["split"] != "test"):
        raise ValueError("expected window must specify a held-out test trial")
    baseline_receipts = (strict_json(baseline_export_receipt), strict_json(baseline_interval_receipt))
    candidate_receipts = (strict_json(candidate_export_receipt), strict_json(candidate_interval_receipt))
    for pair in (baseline_receipts, candidate_receipts):
        if any(type(value) is not dict for value in pair):
            raise ValueError("receipt must be a JSON object")
    # Run the SAME verified capture interval protocol on BOTH cohorts, with
    # independently supplied receipts and no filtered/method-specific truth.
    b_report = evaluate_interval(world, baseline_capture, baseline_receipts[0],
                                 baseline_export_key, baseline_receipts[1],
                                 baseline_interval_key, window, world_pin, baseline_pin)
    c_report = evaluate_interval(world, candidate_capture, candidate_receipts[0],
                                 candidate_export_key, candidate_receipts[1],
                                 candidate_interval_key, window, world_pin, candidate_pin)
    world_rows = rows_from_bytes(world, WORLD_COLUMNS)
    if len(world_rows) > MAX_WORLD_INCIDENTS:
        raise ValueError("world exceeds bounded incident count")
    truths = {}
    for row in world_rows:
        if tuple(row[k] for k in GROUP_FIELDS) != tuple(window[k] for k in GROUP_FIELDS):
            raise ValueError("world and pre-pinned trial identity mismatch")
        incident = row["incident_id"]
        if not incident or incident in truths or row["ground_truth"] not in ("0", "1"):
            raise ValueError("duplicate or invalid world incident")
        truths[incident] = int(row["ground_truth"])
    baseline, b_missing = _predictions(baseline_capture, set(truths))
    candidate, c_missing = _predictions(candidate_capture, set(truths))

    def counts(prediction):
        return {
            "tp": sum(truths[k] == 1 and prediction[k] == 1 for k in truths),
            "tn": sum(truths[k] == 0 and prediction[k] == 0 for k in truths),
            "fp": sum(truths[k] == 0 and prediction[k] == 1 for k in truths),
            "fn": sum(truths[k] == 1 and prediction[k] == 0 for k in truths),
        }

    b_counts, c_counts = counts(baseline), counts(candidate)
    if any(b_report[key] != b_counts[key] or c_report[key] != c_counts[key]
           for key in ("tp", "tn", "fp", "fn")):
        raise ValueError("signed capture join and paired comparison disagree")
    paired = io.StringIO(newline="")
    writer = csv.writer(paired, lineterminator="\n")
    writer.writerow(PAIR_COLUMNS)
    cluster = _trial_identity(window)
    for incident in sorted(truths):
        writer.writerow((_trial_identity(window, incident), cluster, truths[incident],
                         baseline[incident], candidate[incident]))
    paired_bytes = paired.getvalue().encode("utf-8")
    b_correct = {k: baseline[k] == truths[k] for k in truths}
    c_correct = {k: candidate[k] == truths[k] for k in truths}
    b_only = sum(b_correct[k] and not c_correct[k] for k in truths)
    c_only = sum(c_correct[k] and not b_correct[k] for k in truths)
    summary = {
        "schema_version": 1, "publication_ready": False,
        "evidence_class": "matched_hub_export_integrity_not_independent_experimental_evidence",
        "held_out_split": window["split"], "trial_cluster_id": cluster,
        "incidents": len(truths), "independent_clusters_in_this_file": 1,
        "baseline": {**b_counts, "incidents_not_received": b_missing},
        "candidate": {**c_counts, "incidents_not_received": c_missing},
        "candidate_minus_baseline_accuracy_pp": 100.0 * (c_only - b_only) / len(truths),
        "baseline_only_correct": b_only, "candidate_only_correct": c_only,
        "source_sha256": {"world": world_pin, "baseline_capture": baseline_pin,
                          "candidate_capture": candidate_pin, "window": window_pin},
        "paired_csv_sha256": sha256(paired_bytes),
        "limitations": [
            "One scenario/seed is one cluster; incident rows must not be treated as independent trials.",
            "A signed hub completion flag does not prove continuous observation, independent source truth, or physical sensor uptime.",
            "Pre-pinned operator hashes do not prove external pre-registration or publisher provenance.",
            "No hypothesis test or population-level uncertainty is justified by this one-cluster result.",
            "Hardware actuation and vehicle safety are not exercised by offline capture comparisons.",
        ],
    }
    return summary, paired_bytes


def main() -> None:
    p = argparse.ArgumentParser(description="Compare identically scoped V2X capture trials without hardware control")
    for name in ("world", "baseline-capture", "candidate-capture",
                 "baseline-export-receipt", "candidate-export-receipt",
                 "baseline-interval-receipt", "candidate-interval-receipt",
                 "baseline-export-key", "candidate-export-key",
                 "baseline-interval-key", "candidate-interval-key",
                 "expected-window", "output-dir"):
        p.add_argument("--" + name, type=Path, required=True)
    for name in ("world-pin", "baseline-pin", "candidate-pin", "window-pin"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    inputs = (a.world, a.baseline_capture, a.candidate_capture,
              a.baseline_export_receipt, a.candidate_export_receipt,
              a.baseline_interval_receipt, a.candidate_interval_receipt,
              a.baseline_export_key, a.candidate_export_key,
              a.baseline_interval_key, a.candidate_interval_key,
              a.expected_window)
    if any(path.stat().st_size > MAX_ARTIFACT_BYTES for path in inputs):
        p.error("input file exceeds bounded size")
    summary, paired = compare(*(path.read_bytes() for path in inputs),
                              world_pin=a.world_pin, baseline_pin=a.baseline_pin,
                              candidate_pin=a.candidate_pin, window_pin=a.window_pin)
    a.output_dir.mkdir(parents=True, exist_ok=False)
    (a.output_dir / "paired_incidents.csv").write_bytes(paired)
    (a.output_dir / "report.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"output_dir": str(a.output_dir), "publication_ready": False,
                      "paired_csv_sha256": summary["paired_csv_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
