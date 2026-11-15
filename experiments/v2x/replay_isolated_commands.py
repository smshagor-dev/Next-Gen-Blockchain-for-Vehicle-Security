"""Deterministic, simulation-only V2X command replay. No CAN/serial/socket imports.

Input JSONL schema per line: {"incident_id": str, "command": str,
"authenticated": bool, "fresh": bool, "evidence_admitted": bool,
"local_emergency": bool}. All fields required; duplicate IDs rejected.
Only network alert relay can be admitted; never physical actuation.
"""
import argparse
import hashlib
import json
from pathlib import Path

FIELDS = {"incident_id", "command", "authenticated", "fresh",
          "evidence_admitted", "local_emergency"}
COMMANDS = {"alert", "brake", "steer", "throttle", "reset_emergency"}
MAX_BYTES = 16 * 1024 * 1024
MAX_LINES = 100000

def _strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field: " + key)
        result[key] = value
    return result

def _reject_constant(value):
    raise ValueError("non-finite JSON constant: " + value)

def evaluate(event):
    if type(event) is not dict or set(event) != FIELDS:
        raise ValueError("invalid event schema")
    if type(event["incident_id"]) is not str or not event["incident_id"] or len(event["incident_id"]) > 128:
        raise ValueError("invalid incident ID")
    if event["command"] not in COMMANDS:
        raise ValueError("unsupported command")
    for key in FIELDS - {"incident_id", "command"}:
        if type(event[key]) is not bool:
            raise ValueError("boolean required: " + key)
    if event["local_emergency"]:
        return "blocked_local_emergency"
    if event["command"] != "alert":
        return "blocked_actuation_or_reset"
    if not event["authenticated"]:
        return "blocked_authentication"
    if not event["fresh"]:
        return "blocked_replay"
    if not event["evidence_admitted"]:
        return "blocked_evidence"
    return "simulated_alert"

def replay(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError("input exceeds byte limit")
    rows = raw.splitlines()
    if len(rows) > MAX_LINES:
        raise ValueError("input exceeds row limit")
    seen = set()
    output = []
    for line_no, line in enumerate(rows, 1):
        try:
            # Do not silently accept duplicate security gates or non-standard\n            # JSON constants. Such ambiguities break independent replay audits.\n            event = json.loads(line, object_pairs_hook=_strict_pairs,\n                               parse_constant=_reject_constant)
            verdict = evaluate(event)
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            raise ValueError("invalid input at line %d: %s" % (line_no, exc)) from exc
        identifier = event["incident_id"]
        if identifier in seen:
            raise ValueError("duplicate incident ID")
        seen.add(identifier)
        output.append({"incident_id": identifier, "verdict": verdict})
    return {"input_sha256": hashlib.sha256(raw).hexdigest(),
            "events": output, "count": len(output),
            "simulated_alerts": sum(x["verdict"] == "simulated_alert" for x in output),
            "evidence_class": "synthetic_or_unverified_simulation_only"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.input.stat().st_size > MAX_BYTES:
        parser.error("input exceeds byte limit")
    result = replay(args.input.read_bytes())
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
