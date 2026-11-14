"""Conservative incident join scoped to a signed capture-coverage claim.

HMAC authenticates a *hub's claim* that it ran for a window, not physical
coverage, ground-truth independence, or sensor trust. Never publication ready.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path

from join_world_incidents import (CAPTURE_COLUMNS, WORLD_COLUMNS, digest,
                                  evaluate, rows_from_bytes)

FIELDS = ("schema_version", "capture_sha256", "experiment_id", "scenario_id",
          "seed", "split", "window_start", "window_end", "capture_complete")
GROUP_FIELDS = ("experiment_id", "scenario_id", "seed", "split")


def utc(value: str) -> datetime:
    if not isinstance(value, str) or not value or value[-1:] == "z":
        raise ValueError("invalid capture window timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("missing timezone")
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("invalid or timezone-naive capture timestamp") from exc


def receipt_payload(receipt: dict) -> bytes:
    if not isinstance(receipt, dict) or set(receipt) != set(FIELDS) | {"hmac_sha256"}:
        raise ValueError("invalid interval receipt schema")
    fields = {name: receipt[name] for name in FIELDS}
    if type(fields["schema_version"]) is not int or fields["schema_version"] != 1 or type(fields["capture_complete"]) is not bool:
        raise ValueError("unsupported interval receipt version or completion flag")
    if any(not isinstance(fields[name], str) or not fields[name]
           for name in (*GROUP_FIELDS, "capture_sha256", "window_start", "window_end")):
        raise ValueError("invalid interval metadata")
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def evaluate_interval(world: bytes, capture: bytes, export_receipt: dict,
                      export_key: bytes, interval_receipt: dict,
                      interval_key: bytes, expected_window: dict,
                      pinned_world_sha256: str, pinned_capture_sha256: str) -> dict:
    """Evaluate only within operator-selected window and a MAC-bound completion claim.

    expected_window is an out-of-band operator setting, not evidence that it
    was registered before data collection. Never silently clip late records.
    """
    if not interval_key or not isinstance(interval_receipt, dict) or not isinstance(interval_receipt.get("hmac_sha256"), str):
        raise ValueError("missing authenticated interval receipt")
    mac = interval_receipt["hmac_sha256"]
    if len(mac) != 64 or any(c not in "0123456789abcdef" for c in mac):
        raise ValueError("invalid interval receipt HMAC encoding")
    signed = receipt_payload(interval_receipt)
    expected_mac = hmac.new(interval_key, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, interval_receipt["hmac_sha256"]):
        raise ValueError("interval receipt HMAC mismatch")
    if not interval_receipt["capture_complete"]:
        raise ValueError("incomplete interval export; cannot infer full-window absence")
    if not isinstance(expected_window, dict) or set(expected_window) != set(GROUP_FIELDS) | {"window_start", "window_end"}:
        raise ValueError("operator window schema mismatch")
    if any(interval_receipt[k] != expected_window[k] for k in expected_window):
        raise ValueError("signed interval differs from operator-selected window")
    if not hmac.compare_digest(interval_receipt["capture_sha256"], digest(capture)):
        raise ValueError("interval does not bind this capture")
    start, end = utc(interval_receipt["window_start"]), utc(interval_receipt["window_end"])
    if end <= start:
        raise ValueError("empty or reversed interval")
    world_rows = rows_from_bytes(world, WORLD_COLUMNS)
    capture_rows = rows_from_bytes(capture, CAPTURE_COLUMNS, allow_empty=True)
    group = tuple(expected_window[k] for k in GROUP_FIELDS)
    if any(tuple(row[k] for k in GROUP_FIELDS) != group for row in world_rows):
        raise ValueError("world rows differ from operator-selected window")
    if any(tuple(row[k] for k in GROUP_FIELDS) != group for row in capture_rows):
        raise ValueError("capture rows differ from operator-selected window")
    for row in capture_rows:
        stamp = utc(row["received_at"])
        if not start <= stamp < end:
            raise ValueError("capture timestamp outside attested window")
    report = evaluate(world, capture, export_receipt, export_key,
                      pinned_world_sha256, pinned_capture_sha256)
    report["interval_receipt_authenticated"] = True
    report["interval_window_start"] = interval_receipt["window_start"]
    report["interval_window_end"] = interval_receipt["window_end"]
    report["capture_complete_claim_signed"] = True
    report["publication_ready"] = False
    report["limitations"].append(
        "Hub-signed completion is a self-report, not independent proof of observation coverage, availability, or physical sensor uptime.")
    report["limitations"].append(
        "Operator-selected window is not cryptographic proof of pre-registration or independent ground truth.")
    return report


def main() -> None:
    p = argparse.ArgumentParser(description="Signed-window V2X incident join; software integrity evidence only")
    for name in ("world", "capture", "export-receipt", "export-key", "interval-receipt",
                 "interval-key", "expected-window", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--world-sha256", required=True)
    p.add_argument("--capture-sha256", required=True)
    a = p.parse_args()
    report = evaluate_interval(a.world.read_bytes(), a.capture.read_bytes(),
                               json.loads(a.export_receipt.read_text()), a.export_key.read_bytes(),
                               json.loads(a.interval_receipt.read_text()), a.interval_key.read_bytes(),
                               json.loads(a.expected_window.read_text()),
                               a.world_sha256, a.capture_sha256)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    a.output.write_text(payload, encoding="utf-8")
    print(json.dumps({"output_sha256": digest(payload.encode()), "publication_ready": False}))


if __name__ == "__main__":
    main()
