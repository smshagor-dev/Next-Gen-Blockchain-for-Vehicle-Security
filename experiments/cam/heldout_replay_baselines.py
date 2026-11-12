"""Source-split CAM-level misbehavior baselines, evaluated on genuine labels.

This evaluates non-novel, predeclared single-feature heuristics on VeReMi
NextGen *CAM message* attacker labels. It is NOT an incident-admission test,
vehicle safety evaluation, novel algorithm or multi-seed statistical proof.
Deduplicate receiver receptions before fitting validation thresholds or scoring
a held-out source TEST partition. No test labels enter model calibration.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Sequence

REQUIRED = (
    "archive_sha256", "source_split", "receiver_log", "sender_id",
    "sender_alias", "message_id", "send_time_raw", "receive_time_raw",
    "sender_acceleration", "sender_pos_x", "sender_pos_y", "sender_speed", "attacker_label",
)
SPLITS = frozenset(("train", "validation", "test"))
METHODS = (
    "always_benign",
    "receive_age_p99",
    "acceleration_magnitude_p99",
    "age_or_acceleration_p99",
    "temporal_motion_residual_p99",
)


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _integer_timestamp(text: str, field: str, line: int) -> int:
    if not isinstance(text, str) or not text.isdecimal():
        raise ValueError(f"invalid {field} at line {line}; integer source nanoseconds required")
    return int(text)


def _finite_source_float(text: str, field: str, line: int) -> float:
    try:
        value = float(text)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"invalid {field} at line {line}") from exc
    if not math.isfinite(value):
        raise ValueError(f"nonfinite {field} at line {line}")
    return value


def _acceleration(text: str, line: int) -> float:
    return abs(_finite_source_float(text, "sender acceleration", line))


@dataclass(frozen=True)
class Transmission:
    split: str
    key: tuple[str, str, str, str]
    label: int
    receiver_log: str
    age_ns: int
    abs_acceleration_mps2: float
    send_ns: int
    sender_x_m: float
    sender_y_m: float
    sender_speed_mps: float
    motion_residual_mps: float | None = None


def verified_source_manifest(source_csv: Path, manifest_file: Path, expected_archive_sha256: str) -> dict:
    source_csv, manifest_file = Path(source_csv), Path(manifest_file)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("source manifest must be a JSON object")
    real_csv_digest = file_hash(source_csv)
    if manifest.get("normalized_csv_sha256") != real_csv_digest:
        raise ValueError("normalized input SHA-256 mismatch")
    if manifest.get("source_sha256_verified") != expected_archive_sha256:
        raise ValueError("parent publisher ZIP SHA-256 identity mismatch")
    if manifest.get("evaluation_unit") != "per_receiver_CAM_record_not_independent_hazard_incident":
        raise ValueError("input must preserve per-receiver CAM semantics")
    if manifest.get("attack_subset_declared") != "dataReplay":
        raise ValueError("this benchmark accepts explicitly declared dataReplay archive only")
    return {
        "parent_archive_sha256": expected_archive_sha256,
        "source_csv_sha256": real_csv_digest,
        "source_manifest_sha256": file_hash(manifest_file),
    }


def deduplicate_labeled_cams(source_csv: Path, expected_archive_sha256: str, *, max_rows: int = 2_000_000
                             ) -> tuple[dict[str, list[Transmission]], dict[str, int]]:
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    seen: dict[tuple[str, str, str, str], Transmission] = {}
    repeated = 0
    received = 0
    with Path(source_csv).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        missing = set(REQUIRED) - set(reader.fieldnames or ())
        if missing:
            raise ValueError("missing normalized source fields: " + ", ".join(sorted(missing)))
        for line, item in enumerate(reader, 2):
            received += 1
            if received > max_rows:
                raise ValueError("CAM row resource limit exceeded")
            if None in item or any(item.get(key) is None for key in REQUIRED):
                raise ValueError(f"malformed normalized CAM at line {line}")
            if item["archive_sha256"] != expected_archive_sha256:
                raise ValueError(f"archive identity mismatch at line {line}")
            split = item["source_split"]
            if split not in SPLITS:
                raise ValueError(f"unknown or unverified source split at line {line}")
            if item["attacker_label"] not in {"0", "1"}:
                raise ValueError(f"missing or ambiguous ground-truth CAM label at line {line}")
            if not item["receiver_log"].strip():
                raise ValueError(f"receiver log identity missing at line {line}")
            key = tuple(item[col] for col in ("sender_id", "sender_alias", "message_id", "send_time_raw"))
            if any(not field.strip() for field in key):
                raise ValueError(f"transmission fingerprint field missing at line {line}")
            send_ns = _integer_timestamp(item["send_time_raw"], "sendTime", line)
            receive_ns = _integer_timestamp(item["receive_time_raw"], "rcvTime", line)
            age_ns = receive_ns - send_ns  # exact integer precision; source nanoseconds
            trial = Transmission(
                split=split, key=key, label=int(item["attacker_label"]),
                receiver_log=item["receiver_log"], age_ns=age_ns,
                abs_acceleration_mps2=_acceleration(item["sender_acceleration"], line),
                send_ns=send_ns,
                sender_x_m=_finite_source_float(item["sender_pos_x"], "sender_pos_x", line),
                sender_y_m=_finite_source_float(item["sender_pos_y"], "sender_pos_y", line),
                sender_speed_mps=_finite_source_float(item["sender_speed"], "sender_speed", line),
            )
            prior = seen.get(key)
            if prior is not None:
                repeated += 1
                if prior.split != trial.split:
                    raise ValueError("transmission fingerprint crosses train/validation/test source splits")
                if prior.label != trial.label:
                    raise ValueError("conflicting attacker labels on repeated receiver reception")
                # Deterministic aggregation: earliest observed receiver (ties
                # resolved by log path). Duplicates never inflate sample size.
                if (trial.age_ns, trial.receiver_log) < (prior.age_ns, prior.receiver_log):
                    seen[key] = trial
            else:
                seen[key] = trial
    if received == 0:
        raise ValueError("source CSV has no CAM records")
    partitions: dict[str, list[Transmission]] = {name: [] for name in SPLITS}
    for trial in seen.values():
        partitions[trial.split].append(trial)
    if any(not partitions[p] for p in SPLITS):
        raise ValueError("source train, validation and test splits must all be present and nonempty")
    for split in SPLITS:
        partitions[split].sort(key=lambda trial: trial.key)
    audit = {
        "received_cam_receptions": received,
        "distinct_transmission_fingerprints": len(seen),
        "deduplicated_receiver_receptions": repeated,
        **{f"{p}_distinct_fingerprints": len(partitions[p]) for p in sorted(SPLITS)},
        **{f"{p}_attacker_one": sum(t.label for t in partitions[p]) for p in sorted(SPLITS)},
        **{f"{p}_attacker_zero": sum(1 - t.label for t in partitions[p]) for p in sorted(SPLITS)},
    }
    return partitions, audit


def annotate_motion_consistency(partitions: dict[str, list[Transmission]]) -> dict[str, list[Transmission]]:
    """Compute sender-claimed planar motion residual without sharing state across source splits.

    Invalid/non-increasing time, initial sender message or gaps over five seconds
    produce no temporal feature and must not inflate measured detection.
    """
    annotated: dict[str, list[Transmission]] = {}
    for split, trials in partitions.items():
        sender_series: dict[tuple[str, str], list[Transmission]] = {}
        for trial in trials:
            sender_series.setdefault((trial.key[0], trial.key[1]), []).append(trial)
        derived: dict[tuple[str, str, str, str], Transmission] = {}
        for group in sender_series.values():
            ordered = sorted(group, key=lambda t: (t.send_ns, t.key[2]))
            previous = None
            for current in ordered:
                residual = None
                if previous is not None:
                    elapsed = current.send_ns - previous.send_ns
                    if 0 < elapsed <= 5_000_000_000:
                        distance_m = math.hypot(
                            current.sender_x_m - previous.sender_x_m,
                            current.sender_y_m - previous.sender_y_m,
                        )
                        estimated_speed_mps = distance_m * 1_000_000_000 / elapsed
                        residual = abs(estimated_speed_mps - current.sender_speed_mps)
                        if not math.isfinite(residual):
                            raise ValueError("nonfinite computed temporal motion residual")
                derived[current.key] = replace(current, motion_residual_mps=residual)
                previous = current
        annotated[split] = [derived[t.key] for t in trials]
    return annotated


def _nearest_rank(values: list[float | int], q: float) -> float | int:
    if not values or not 0 < q < 1:
        raise ValueError("negative validation reference samples and quantile in (0, 1) required")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def calibrate(validation: list[Transmission], *, quantile: float = 0.99) -> dict:
    benign = [t for t in validation if t.label == 0]
    if len(benign) < 20:
        raise ValueError("at least 20 distinct benign validation CAM fingerprints required")
    motion_benign = [t.motion_residual_mps for t in benign if t.motion_residual_mps is not None]
    if len(motion_benign) < 20:
        raise ValueError("at least 20 motion-eligible benign validation fingerprints required")
    return {
        "quantile": quantile,
        "calibration_partition": "publisher_validation_distinct_fingerprints",
        "temporal_validation_eligible_benign": len(motion_benign),
        "motion_gap_limit_seconds": 5,
        "motion_feature_absent_policy": "predict_negative_and_report_coverage",
        "benign_validation_fingerprints": len(benign),
        "age_ns_upper": _nearest_rank([t.age_ns for t in benign], quantile),
        "acceleration_abs_mps2_upper": _nearest_rank([t.abs_acceleration_mps2 for t in benign], quantile),
        "temporal_motion_residual_mps_upper": _nearest_rank(motion_benign, quantile),
        "threshold_rule": "strictly_greater_than_calibrated_negative_validation_quantile",
    }


def predictions(test: list[Transmission], calibration: dict, method: str) -> list[bool]:
    if method not in METHODS:
        raise ValueError("unknown or unregistered baseline")
    age_threshold = calibration["age_ns_upper"]
    acceleration_threshold = calibration["acceleration_abs_mps2_upper"]
    if method == "always_benign":
        return [False for _ in test]
    if method == "receive_age_p99":
        return [t.age_ns > age_threshold for t in test]
    if method == "acceleration_magnitude_p99":
        return [t.abs_acceleration_mps2 > acceleration_threshold for t in test]
    if method == "temporal_motion_residual_p99":
        return [
            t.motion_residual_mps is not None
            and t.motion_residual_mps > calibration["temporal_motion_residual_mps_upper"]
            for t in test
        ]
    return [t.age_ns > age_threshold or t.abs_acceleration_mps2 > acceleration_threshold for t in test]


def metrics(test: list[Transmission], pred: list[bool]) -> dict[str, Any]:
    if len(test) != len(pred) or not test:
        raise ValueError("prediction and held-out CAM count mismatch")
    tp = sum(p and t.label == 1 for t, p in zip(test, pred))
    fp = sum(p and t.label == 0 for t, p in zip(test, pred))
    fn = sum(not p and t.label == 1 for t, p in zip(test, pred))
    tn = sum(not p and t.label == 0 for t, p in zip(test, pred))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "support": len(test), "positive_support": tp + fn, "negative_support": tn + fp,
        "temporal_motion_feature_available": sum(t.motion_residual_mps is not None for t in test),
        "precision": precision, "recall": recall, "specificity": specificity,
        "f1": f1, "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None,
    }


def run(source_csv: Path, manifest_path: Path, output_dir: Path, *,
        expected_archive_sha256: str, quantile: float = 0.99) -> dict[str, Any]:
    if len(expected_archive_sha256) != 64 or any(x not in "0123456789abcdef" for x in expected_archive_sha256):
        raise ValueError("expected archive digest must be 64 lowercase hexadecimal characters")
    hashes = verified_source_manifest(source_csv, manifest_path, expected_archive_sha256)
    partitions, audit = deduplicate_labeled_cams(source_csv, expected_archive_sha256)
    partitions = annotate_motion_consistency(partitions)
    calibration = calibrate(partitions["validation"], quantile=quantile)
    test = partitions["test"]
    result = {
        "status": "real_source_cam_level_descriptive_heldout_baselines",
        "evaluation_unit": "unique_sender_pseudonym_messageid_sendtime_fingerprint",
        "dataset": "VeReMi NextGen v1.0.0 InTAS_highway_2_dataReplay",
        "publication_ready": False, "statistical_significance": False,
        "source_hashes": hashes, "split_audit": audit, "thresholds": calibration,
        "methods": {method: metrics(test, predictions(test, calibration, method)) for method in METHODS},
        "limitations": [
            "Only VeReMi dataReplay CAM attacker=0/1 labels are evaluated; not hazard-event ground truth or physical V2X admission effectiveness.",
            "Repeated receiver receptions are deduplicated with a heuristic fingerprint, which may conflate collisions or distinct retransmissions.",
            "An exact matching fingerprint across source train/validation/test is rejected, but identity and simulation-scene leakage beyond this key is not ruled out.",
            "The negative-validation nearest-rank 99th-percentile threshold was predeclared and never tuned on test observations.",
            "Heuristic methods are NOT new algorithms, competitive published detector reproductions, or validated original research contributions.",
            "Temporal residual is derived from claimed sender position and speed, not physical sensor attestation; initial/gapped observations are missing this feature.",
            "One official archive and one publisher test split do not justify independent-run statistics, confirmatory significance, external validity, or safety claims.",
            "Dataset licensing and independent provenance beyond verified source ZIP hashes require separate review.",
        ],
    }
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    json_file, csv_file = target / "cam_heldout_results.json", target / "cam_heldout_results.csv"
    json_file.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    with csv_file.open("w", encoding="utf-8", newline="") as out:
        fields = ["method", "tp", "fp", "tn", "fn", "support", "positive_support", "negative_support",
                  "precision", "recall", "specificity", "f1", "false_positive_rate", "balanced_accuracy", "temporal_motion_feature_available"]
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        writer.writerows({"method": name, **measures} for name, measures in result["methods"].items())
    evidence = {
        "input_sha256": hashes["source_csv_sha256"],
        "source_manifest_sha256": hashes["source_manifest_sha256"],
        "publisher_zip_sha256": hashes["parent_archive_sha256"],
        "results_sha256": {p.name: file_hash(p) for p in (json_file, csv_file)},
        "publication_ready": False,
    }
    (target / "cam_heldout_manifest.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Leakage-guarded held-out dataReplay CAM baseline; NOT incident efficacy.")
    parser.add_argument("--source-csv", required=True)
    parser.add_argument("--source-manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--expected-archive-sha256", required=True)
    args = parser.parse_args(argv)
    outcome = run(
        Path(args.source_csv), Path(args.source_manifest), Path(args.output_dir),
        expected_archive_sha256=args.expected_archive_sha256,
    )
    print(json.dumps({"status": outcome["status"], "split_audit": outcome["split_audit"],
                      "methods": outcome["methods"], "publication_ready": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
