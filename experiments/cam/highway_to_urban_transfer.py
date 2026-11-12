"""Frozen highway-to-urban CAM heuristic transfer, not a V2X incident study.

Independent *publisher scenario* evaluation, but NOT an independently repeated
experiment, preregistered confirmatory finding or proof of original novelty.

The only calibration source is highway_2 Validation benign fingerprints.
The urban_2 dataset is parsed only after thresholds have been fixed and is
scored on its original Test partition; no urban validation/test labels are
allowed to select methods, features, thresholds, gap limits or quantiles.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Sequence

from experiments.cam.heldout_replay_baselines import (
    METHODS,
    annotate_motion_consistency,
    calibrate,
    deduplicate_labeled_cams,
    file_hash,
    metrics,
    predictions,
    verified_source_manifest,
)

SOURCE_NAME = "InTAS_highway_2_dataReplay"
TARGET_NAME = "InTAS_urban_2_dataReplay"
SOURCE_SHA256 = "08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea"
TARGET_SHA256 = "9984cd0cfa32d31f607788a2a1c53c72970c6786563c785cce9b989bb7ce7777"
FIXED_QUANTILE = 0.99
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def _validate_release_identity(
    source_csv: Path, source_manifest: Path,
    target_csv: Path, target_manifest: Path,
    source_sha256: str, target_sha256: str,
) -> dict[str, dict]:
    if not _DIGEST.fullmatch(source_sha256) or not _DIGEST.fullmatch(target_sha256):
        raise ValueError("source and target ZIP digests must be lowercase SHA-256")
    if source_sha256 == target_sha256:
        raise ValueError("source and target must be different publisher archives")
    origin = verified_source_manifest(source_csv, source_manifest, source_sha256)
    target = verified_source_manifest(target_csv, target_manifest, target_sha256)
    return {"calibration_source": origin, "external_evaluation": target}


def run_transfer(
    source_csv: Path, source_manifest: Path,
    target_csv: Path, target_manifest: Path,
    output_dir: Path, *,
    source_sha256: str = SOURCE_SHA256,
    target_sha256: str = TARGET_SHA256,
) -> dict[str, Any]:
    """Use SHA-verified genuine release CSVs, calibrate on highway, score urban.

    The pair of SHA-256 values is pinned to distinct official v1.0.0 artifacts
    by default. Alternate digests are only intended for synthetic unit tests
    and must be called explicitly by the test, not CLI or CI.
    """
    hashes = _validate_release_identity(
        source_csv, source_manifest, target_csv, target_manifest,
        source_sha256, target_sha256,
    )

    # Source-only calibration happens before target CAMs are even parsed.
    source_parts, source_audit = deduplicate_labeled_cams(source_csv, source_sha256)
    source_parts = annotate_motion_consistency(source_parts)
    frozen = calibrate(source_parts["validation"], quantile=FIXED_QUANTILE)

    # No target-validation refitting is permitted. This pass does validate
    # every target split's labels, fingerprint duplicates and leakage.
    target_parts, target_audit = deduplicate_labeled_cams(target_csv, target_sha256)
    source_keys = {t.key for rows in source_parts.values() for t in rows}
    target_keys = {t.key for rows in target_parts.values() for t in rows}
    matching = source_keys.intersection(target_keys)
    if matching:
        raise ValueError(
            f"source/target fingerprint intersection detected ({len(matching)}); "
            "external-study leakage cannot be silently ignored"
        )
    target_parts = annotate_motion_consistency(target_parts)
    test = target_parts["test"]
    if not any(t.label == 0 for t in test) or not any(t.label == 1 for t in test):
        raise ValueError("external target Test split needs positive and negative CAM labels")

    methods = {
        name: metrics(test, predictions(test, frozen, name))
        for name in METHODS
    }
    result = {
        "status": "exploratory_cross_scenario_cam_transfer",
        "publication_ready": False,
        "confirmatory_study": False,
        "statistical_significance": False,
        "not_original_algorithm": True,
        "source_release": SOURCE_NAME,
        "target_release": TARGET_NAME,
        "publisher_tag": "v1.0.0",
        "evaluation_unit": "deduplicated_cam_transmission_fingerprint_not_physical_incident",
        "source_hashes": hashes,
        "source_fingerprint_audit": source_audit,
        "target_fingerprint_audit": target_audit,
        "cross_scenario_matching_fingerprints": 0,
        "calibration_partition": "source_highway_2_validation_benign_only",
        "evaluation_partition": "target_urban_2_test_only",
        "calibration_quantile": FIXED_QUANTILE,
        "source_frozen_thresholds": frozen,
        "methods": methods,
        "study_provenance": {
            "first_highway_test_results_seen_before_temporal_comparator_added": True,
            "urban_target_not_used_to_fit_any_threshold": True,
            "urban_2_selected_after_previous_highway_results_seen": True,
            "formal_preregistration": False,
            "independent_repetitions": 0,
        },
        "limitations": [
            "CAM attacker labels do not describe actual physical road hazard incidents or vehicle authorization decisions.",
            "Source highway_2 Test results were examined before the post-hoc temporal feature was defined; this external check is exploratory rather than confirmatory.",
            "Urban_2 source was selected after inspecting highway_2 results; no preregistered multi-scenario study was conducted.",
            "Only one distinct target urban publisher scenario is evaluated, without independently repeated simulation seeds or uncertainty intervals.",
            "The source and target are from the same published VeReMi family and may share simulation mechanisms, attack generators or confounders.",
            "Matching sender+alias+messageID+sendTime fingerprints are a heuristic leakage check, not proof of independent physical transmissions or vehicles.",
            "All features use sender-reported values and are not certified physical ground truth.",
            "No published SOTA trust/detection algorithm, distributed event-admission test, local emergency safety or hardware-in-loop validation is performed.",
            "Dataset license and source label quality need independent scrutiny before research publication.",
        ],
    }
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "cam_transfer_results.json"
    table_path = output_dir / "cam_transfer_results.csv"
    provenance_path = output_dir / "cam_transfer_provenance.json"
    report_path.write_text(
        json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    with table_path.open("w", encoding="utf-8", newline="") as handle:
        fields = (
            "method", "tp", "fp", "tn", "fn", "support",
            "positive_support", "negative_support", "precision", "recall",
            "specificity", "f1", "false_positive_rate", "balanced_accuracy",
            "temporal_motion_feature_available",
        )
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({"method": name, **score} for name, score in methods.items())
    provenance = {
        "source_archive_sha256": source_sha256,
        "target_archive_sha256": target_sha256,
        "normalized_source_sha256": hashes["calibration_source"]["source_csv_sha256"],
        "normalized_target_sha256": hashes["external_evaluation"]["source_csv_sha256"],
        "result_json_sha256": file_hash(report_path),
        "result_csv_sha256": file_hash(table_path),
        "publication_ready": False,
    }
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    cli = argparse.ArgumentParser(
        description="Apply frozen highway-2 validation thresholds to an independent urban-2 CAM Test scenario."
    )
    cli.add_argument("--highway-csv", required=True)
    cli.add_argument("--highway-manifest", required=True)
    cli.add_argument("--urban-csv", required=True)
    cli.add_argument("--urban-manifest", required=True)
    cli.add_argument("--output-dir", required=True)
    args = cli.parse_args(argv)
    report = run_transfer(
        Path(args.highway_csv), Path(args.highway_manifest),
        Path(args.urban_csv), Path(args.urban_manifest), Path(args.output_dir),
    )
    print(json.dumps({
        "status": report["status"],
        "calibration_partition": report["calibration_partition"],
        "evaluation_partition": report["evaluation_partition"],
        "target_fingerprints": report["target_fingerprint_audit"]["test_distinct_fingerprints"],
        "methods": report["methods"],
        "publication_ready": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
