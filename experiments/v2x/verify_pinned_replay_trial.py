"""Bind replay outputs to a pre-pinned trial manifest; software integrity only.

The manifest must be independently archived BEFORE execution. A matching digest
alone does not prove pre-registration, sensor availability, or source authenticity.
"""
import argparse
import hashlib
import json
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
HEX = set("0123456789abcdef")
FIELDS = {"schema_version", "experiment_id", "scenario_id", "seed", "split",
          "input_sha256", "truth_sha256", "capture_sha256", "policy_sha256",
          "window_start", "window_end"}
GROUP = ("experiment_id", "scenario_id", "seed", "split")

def strict_pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON key")
        result[k] = v
    return result

def parse(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError("oversized artifact")
    return json.loads(raw, object_pairs_hook=strict_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest_field(value):
    return type(value) is str and len(value) == 64 and set(value) <= HEX

def verify(manifest_raw, replay_input_raw, replay_output_raw, truth_raw,
           capture_raw, policy_raw, expected_manifest_sha256):
    if not digest_field(expected_manifest_sha256) or sha(manifest_raw) != expected_manifest_sha256:
        raise ValueError("out-of-band manifest pin mismatch")
    manifest = parse(manifest_raw)
    if type(manifest) is not dict or set(manifest) != FIELDS or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("invalid manifest schema")
    for k in GROUP:
        v = manifest[k]
        if type(v) is not str or not v or len(v) > 128 or any(ord(c) < 32 for c in v):
            raise ValueError("invalid trial identity")
    if manifest["split"] != "test":
        raise ValueError("only held-out test trials accepted")
    for k in ("input_sha256", "truth_sha256", "capture_sha256", "policy_sha256"):
        if not digest_field(manifest[k]):
            raise ValueError("invalid pinned digest")
    for key, raw in (("input_sha256", replay_input_raw), ("truth_sha256", truth_raw),
                     ("capture_sha256", capture_raw), ("policy_sha256", policy_raw)):
        if len(raw) > MAX_BYTES or sha(raw) != manifest[key]:
            raise ValueError(key + " mismatch")
    from datetime import datetime, timezone
    def timestamp(v):
        if type(v) is not str or not v or v.endswith("z"):
            raise ValueError("invalid timestamp")
        try:
            t = datetime.fromisoformat(v.replace("Z", "+00:00"))
            if t.utcoffset() is None:
                raise ValueError("naive timestamp")
            return t.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError) as e:
            raise ValueError("invalid timestamp") from e
    if timestamp(manifest["window_end"]) <= timestamp(manifest["window_start"]):
        raise ValueError("invalid trial window")
    replay = parse(replay_output_raw)
    if type(replay) is not dict or replay.get("input_sha256") != manifest["input_sha256"]:
        raise ValueError("replay does not bind pinned input")
    events = replay.get("events")
    if type(events) is not list or type(replay.get("count")) is not int or replay["count"] != len(events):
        raise ValueError("invalid replay count")
    allowed = {"simulated_alert", "blocked_local_emergency", "blocked_actuation_or_reset",
               "blocked_authentication", "blocked_replay", "blocked_evidence"}
    seen = set()
    for event in events:
        if type(event) is not dict or set(event) != {"incident_id", "verdict"}:
            raise ValueError("invalid decision")
        incident, verdict = event["incident_id"], event["verdict"]
        if type(incident) is not str or not incident or len(incident) > 128 or incident in seen or verdict not in allowed:
            raise ValueError("invalid or duplicate decision")
        seen.add(incident)
    if type(replay.get("simulated_alerts")) is not int or replay["simulated_alerts"] != sum(e["verdict"] == "simulated_alert" for e in events):
        raise ValueError("invalid alert count")
    return {"manifest_sha256": expected_manifest_sha256, "replay_output_sha256": sha(replay_output_raw),
            "trial": {k: manifest[k] for k in GROUP}, "decision_count": len(events),
            "publication_ready": False,
            "limitations": ["Manifest pin must be externally timestamped before execution.",
                            "Capture digest does not prove completeness or sensor uptime.",
                            "Ground-truth digest does not establish annotation independence."]}

def main():
    p = argparse.ArgumentParser()
    for name in ("manifest", "replay-input", "replay-output", "truth", "capture", "policy", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--expected-manifest-sha256", required=True)
    a = p.parse_args()
    paths = [a.manifest, a.replay_input, a.replay_output, a.truth, a.capture, a.policy]
    if any(path.stat().st_size > MAX_BYTES for path in paths):
        p.error("oversized artifact")
    result = verify(*(path.read_bytes() for path in paths), a.expected_manifest_sha256)
    a.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
