"""Operator-pinned trial planning and hub-side receipt construction.

This is source-integrity plumbing, not proof of independent truth, complete
observation, prior registration, vehicle safety or scientific efficacy.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path

from attested_interval_join import (GROUP_FIELDS, evaluate_interval,
                                    receipt_payload, utc)
from join_world_incidents import (WORLD_COLUMNS, CAPTURE_COLUMNS, digest,
                                  evaluate, rows_from_bytes)

PLAN_FIELDS = (*GROUP_FIELDS, "window_start", "window_end",
               "independent_cluster_id", "baseline_name", "candidate_name")
MANIFEST_FIELDS = ("schema_version", "world_sha256", *PLAN_FIELDS)
WINDOW_FIELDS = (*GROUP_FIELDS, "window_start", "window_end")


def canonical(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def make_manifest(plan: dict, world_bytes: bytes) -> bytes:
    if not isinstance(plan, dict) or set(plan) != set(PLAN_FIELDS):
        raise ValueError("trial plan has missing or unexpected fields")
    if any(not isinstance(plan[k], str) or not plan[k].strip()
           for k in PLAN_FIELDS):
        raise ValueError("trial plan must use nonempty strings")
    if plan["baseline_name"] == plan["candidate_name"]:
        raise ValueError("baseline and candidate must differ")
    if utc(plan["window_end"]) <= utc(plan["window_start"]):
        raise ValueError("trial interval must have positive duration")
    world = rows_from_bytes(world_bytes, WORLD_COLUMNS)
    group = tuple(plan[k] for k in GROUP_FIELDS)
    if any(tuple(row[k] for k in GROUP_FIELDS) != group for row in world):
        raise ValueError("independent world universe differs from trial plan")
    if any(row["ground_truth"] not in ("0", "1") for row in world):
        raise ValueError("independent world labels must be binary")
    ids = [row["incident_id"] for row in world]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate incident in world universe")
    result = {"schema_version": 1, "world_sha256": digest(world_bytes), **plan}
    return canonical(result)


def verify_manifest(manifest_bytes: bytes, world_bytes: bytes, pinned_sha256: str) -> dict:
    if not isinstance(pinned_sha256, str) or not hmac.compare_digest(
            digest(manifest_bytes), pinned_sha256):
        raise ValueError("operator-pinned manifest digest mismatch")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid trial manifest JSON") from exc
    if not isinstance(manifest, dict) or set(manifest) != set(MANIFEST_FIELDS):
        raise ValueError("trial manifest schema mismatch")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("unsupported trial manifest version")
    expected = make_manifest({k: manifest[k] for k in PLAN_FIELDS}, world_bytes)
    if manifest_bytes != expected:
        raise ValueError("noncanonical or source-mismatched trial manifest")
    return manifest


def seal_capture(manifest_bytes: bytes, pinned_manifest_sha256: str,
                 world_bytes: bytes, capture_bytes: bytes,
                 export_key: bytes, interval_key: bytes, *,
                 capture_complete: bool = False) -> tuple[dict, dict]:
    """Sign two compatible receipts, after source/split/time validation.

    capture_complete is an explicit *operator assertion*; it must never be
    inferred from number of rows, last timestamp, or an HMAC. A hub with no
    independent uptime witness cannot prove the assertion.
    """
    if type(capture_complete) is not bool:
        raise ValueError("completion assertion must be a boolean")
    if not isinstance(export_key, bytes) or not isinstance(interval_key, bytes) or (
            len(export_key) < 16 or len(interval_key) < 16):
        raise ValueError("independent receipt secrets must be at least 16 bytes")
    if hmac.compare_digest(export_key, interval_key):
        raise ValueError("use distinct export and interval receipt secrets")

    manifest = verify_manifest(manifest_bytes, world_bytes, pinned_manifest_sha256)
    rows = rows_from_bytes(capture_bytes, CAPTURE_COLUMNS, allow_empty=True)
    group = tuple(manifest[k] for k in GROUP_FIELDS)
    start, end = utc(manifest["window_start"]), utc(manifest["window_end"])
    for row in rows:
        if tuple(row[k] for k in GROUP_FIELDS) != group:
            raise ValueError("hub capture trial/seed/split mismatch")
        if not start <= utc(row["received_at"]) < end:
            raise ValueError("hub capture timestamp outside planned window")

    export_receipt = {
        "capture_sha256": digest(capture_bytes),
        "hmac_sha256": hmac.new(export_key, capture_bytes, hashlib.sha256).hexdigest()
    }
    # Check duplicate nonces, unknown incidents and unverified alerts before signing.
    evaluate(world_bytes, capture_bytes, export_receipt, export_key,
             manifest["world_sha256"], digest(capture_bytes))
    interval_receipt = {
        "schema_version": 1,
        "capture_sha256": digest(capture_bytes),
        **{k: manifest[k] for k in WINDOW_FIELDS},
        "capture_complete": capture_complete,
        "hmac_sha256": "0" * 64
    }
    interval_receipt["hmac_sha256"] = hmac.new(
        interval_key, receipt_payload(interval_receipt), hashlib.sha256
    ).hexdigest()
    if capture_complete:
        # Consumer-side round trip: identical protocol, independent world,
        # complete-window validation and incident confusion accounting.
        evaluate_interval(world_bytes, capture_bytes, export_receipt, export_key,
                          interval_receipt, interval_key,
                          {k: manifest[k] for k in WINDOW_FIELDS},
                          manifest["world_sha256"], digest(capture_bytes))
    return export_receipt, interval_receipt


def create_once(path: Path, payload: bytes) -> None:
    """Publish fully fsynced evidence without exposing a partially written file.

    A temporary file in the destination directory is fsynced first, then
    hard-linked to the final name with no overwrite. The link is the atomic
    visibility point. This is NOT atomicity across multiple receipt files.
    """
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".capture-pending-", suffix=".tmp",
                dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            if os.name == "posix":
                os.chmod(temporary, 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # os.link is exclusive: unlike os.replace it fails if target exists.
        os.link(temporary, path)
        if os.name == "posix":
            directory = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Trial manifest and hub export receipt producer")
    subs = parser.add_subparsers(dest="command", required=True)
    plan = subs.add_parser("plan", help="Create exclusive canonical manifest and print SHA-256 for external pinning")
    plan.add_argument("--plan", type=Path, required=True)
    plan.add_argument("--world", type=Path, required=True)
    plan.add_argument("--out", type=Path, required=True)
    seal = subs.add_parser("seal", help="Create exclusive signed capture receipts")
    for name in ("manifest", "world", "capture", "export-key-file", "interval-key-file",
                 "export-receipt-out", "interval-receipt-out"):
        seal.add_argument("--" + name, type=Path, required=True)
    seal.add_argument("--pinned-manifest-sha256", required=True)
    seal.add_argument("--capture-complete", action="store_true",
                      help="Explicit operator claim, NOT proof of sensor uptime")
    args = parser.parse_args()
    if args.command == "plan":
        data = make_manifest(json.loads(args.plan.read_text(encoding="utf-8")),
                             args.world.read_bytes())
        create_once(args.out, data)
        print(json.dumps({"manifest_sha256": digest(data),
                          "external_pin_required": True, "publication_ready": False}))
        return
    if args.export_receipt_out.resolve() == args.interval_receipt_out.resolve():
        raise ValueError("receipt output paths must be different")
    if args.export_receipt_out.exists() or args.interval_receipt_out.exists():
        raise FileExistsError("refuse to overwrite existing evidence receipt")
    exporter, interval = seal_capture(
        args.manifest.read_bytes(), args.pinned_manifest_sha256,
        args.world.read_bytes(), args.capture.read_bytes(),
        args.export_key_file.read_bytes(), args.interval_key_file.read_bytes(),
        capture_complete=args.capture_complete)
    create_once(args.export_receipt_out, canonical(exporter))
    create_once(args.interval_receipt_out, canonical(interval))
    print(json.dumps({"capture_sha256": exporter["capture_sha256"],
                      "capture_complete_claim": args.capture_complete,
                      "publication_ready": False,
                      "warning": "hub self-attestation is not independent coverage evidence"}))


if __name__ == "__main__":
    main()
