"""Fail-closed receipt-pair verification before incident scoring.

A pair is not committed merely because one or both receipt paths exist.
This module verifies their cryptographic binding and trial scope together.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path

from attested_interval_join import evaluate_interval, receipt_payload
from capture_export_producer import WINDOW_FIELDS, verify_manifest
from join_world_incidents import digest


def load_strict_json(data: bytes) -> dict:
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate JSON key")
            obj[key] = value
        return obj
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("malformed or duplicate-key receipt JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("receipt must be an object")
    return value


def verify_pair(world: bytes, capture: bytes, manifest_bytes: bytes,
                pinned_manifest_sha256: str, export_receipt_bytes: bytes,
                interval_receipt_bytes: bytes, export_key: bytes,
                interval_key: bytes) -> dict:
    if not isinstance(export_key, bytes) or not isinstance(interval_key, bytes):
        raise ValueError("receipt keys must be bytes")
    if len(export_key) < 16 or len(interval_key) < 16:
        raise ValueError("receipt keys too short")
    if hmac.compare_digest(export_key, interval_key):
        raise ValueError("receipt keys must be independent")
    manifest = verify_manifest(manifest_bytes, world, pinned_manifest_sha256)
    export = load_strict_json(export_receipt_bytes)
    interval = load_strict_json(interval_receipt_bytes)
    if set(export) != {"capture_sha256", "hmac_sha256"}:
        raise ValueError("invalid export receipt schema")
    if set(interval) != set(WINDOW_FIELDS) | {
            "schema_version", "capture_sha256", "capture_complete", "hmac_sha256"}:
        raise ValueError("invalid interval receipt schema")
    if not hmac.compare_digest(export["capture_sha256"], interval["capture_sha256"]):
        raise ValueError("receipts bind different captures")
    if not hmac.compare_digest(export["capture_sha256"], digest(capture)):
        raise ValueError("receipts do not bind supplied capture")
    if not interval["capture_complete"]:
        raise ValueError("incomplete capture: cannot score absence as observation")
    report = evaluate_interval(
        world, capture, export, export_key, interval, interval_key,
        {key: manifest[key] for key in WINDOW_FIELDS},
        manifest["world_sha256"], digest(capture))
    report["receipt_pair_verified"] = True
    report["pinned_manifest_sha256"] = pinned_manifest_sha256
    report["publication_ready"] = False
    report["limitations"].append(
        "Both hub-signed receipts prove data binding, not independent physical "
        "coverage or pre-run registration; unpaired receipt files must be rejected.")
    return report


def main():
    parser = argparse.ArgumentParser(description="Verify BOTH V2X receipts before scoring")
    for field in ("world", "capture", "manifest", "export-receipt",
                  "interval-receipt", "export-key-file", "interval-key-file", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--pinned-manifest-sha256", required=True)
    args = parser.parse_args()
    report = verify_pair(
        args.world.read_bytes(), args.capture.read_bytes(),
        args.manifest.read_bytes(), args.pinned_manifest_sha256,
        args.export_receipt.read_bytes(), args.interval_receipt.read_bytes(),
        args.export_key_file.read_bytes(), args.interval_key_file.read_bytes())
    payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
    args.output.write_text(payload, encoding="utf-8")
    print(json.dumps({"report_sha256": digest(payload.encode()),
                      "publication_ready": False}))


if __name__ == "__main__":
    main()
