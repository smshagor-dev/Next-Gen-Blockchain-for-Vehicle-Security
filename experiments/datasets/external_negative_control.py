"""Independently published real-world *no-collision* V2X CAM descriptive control.

No event/incident detection rate is computed. Zenodo collection description
says no physical collision occurred; a message row is NOT independently
reviewed hazard truth or a cryptographically authenticated hub session.
No synthetic hazard messages, pseudo-incidents or false-positive denominators
are fabricated from these CAM records.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

SOURCE_DOI = "10.5281/zenodo.21644263"
SOURCE_FILE = "cam.csv"
PUBLISHER_MD5 = "8e4e0dfde05fa46b4f66bf92efbbe70f"
SOURCE_URL = "https://zenodo.org/records/21644263"
SCHEMA = "real-world-negative-control-descriptive-v1"
HEX32 = re.compile(r"^[a-f0-9]{32}$")
MAX_BYTES = 64 * 1024 * 1024
MAX_ROWS = 1_000_000
MAX_FIELDS = 512

def describe(source: Path, output: Path, *, expected_md5: str) -> dict:
    source = Path(source)
    if (not HEX32.fullmatch(expected_md5 or "")
            or not source.is_file() or source.is_symlink()
            or source.stat().st_size == 0 or source.stat().st_size > MAX_BYTES):
        raise ValueError("missing/oversize source or invalid externally pinned MD5")
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with source.open("rb") as fd:
        while chunk := fd.read(1024 * 1024):
            md5.update(chunk)
            sha256.update(chunk)
    if md5.hexdigest() != expected_md5:
        raise ValueError("publisher file digest mismatch")
    with source.open("r", encoding="utf-8-sig", newline="") as fd:
        head = fd.read(8192)
        fd.seek(0)
        # CSV dialect is detected only from syntax, never from data semantics.
        # Restrict to expected CSV separators and let strict CSV parsing reject
        # anomalous/partial rows rather than silently correcting source data.
        candidates = {d: head.splitlines()[0].count(d) for d in (",", ";", "\t")}
        delimiter = max(candidates, key=candidates.get)
        if candidates[delimiter] == 0:
            raise ValueError("source has no recognizable CSV column delimiters")
        csv.field_size_limit(1024 * 1024)
        reader = csv.reader(fd, delimiter=delimiter, strict=True)
        headers = next(reader, None)
        if (not headers or len(headers) > MAX_FIELDS
                or len(headers) < 2
                or any(not h.strip() for h in headers)
                or len(headers) != len(set(headers))):
            raise ValueError("invalid duplicate/empty/oversized CAM schema")
        count = 0
        for row in reader:
            if len(row) != len(headers):
                raise ValueError("truncated or irregular source CSV row")
            count += 1
            if count > MAX_ROWS:
                raise ValueError("excessive CAM records")
        if count == 0:
            raise ValueError("CAM source has no data rows")
    outcome = {
        "schema_version": SCHEMA,
        "source": SOURCE_URL,
        "dataset_doi": SOURCE_DOI,
        "source_filename": SOURCE_FILE,
        "observed_cam_rows": count,
        "source_columns": headers,
        "source_size_bytes": source.stat().st_size,
        "source_md5": md5.hexdigest(),
        "source_sha256": sha256.hexdigest(),
        "publisher_no_collision_claim": True,
        "direct_independent_collision_truth_verified": False,
        "live_authenticated_hub_capture_verified": False,
        "source_enrollment_verified": False,
        "v2x_incident_accuracy_measurable": False,
        "physical_hil_validated": False,
        "publication_ready": False,
        "interpretation": (
            "External no-collision-described CAM dataset syntax and file identity "
            "only. Does not provide independently labeled incident opportunities "
            "or matching hub telemetry and cannot estimate false admission rates."
        ),
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(outcome, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return outcome

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-md5", default=PUBLISHER_MD5)
    a = parser.parse_args()
    print(json.dumps({
        key: value for key, value in describe(
            a.source, a.output, expected_md5=a.expected_md5
        ).items() if key in (
            "observed_cam_rows", "source_sha256", "publication_ready",
            "v2x_incident_accuracy_measurable"
        )
    }, sort_keys=True))

if __name__ == "__main__":
    main()
