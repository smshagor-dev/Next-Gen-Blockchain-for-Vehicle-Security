"""Verify out-of-band pinned bytes before running paired incident scoring.

This is an integrity gate, NOT evidence of publisher authenticity or preregistration.
"""
import argparse
import hashlib
import json
from pathlib import Path

from experiments.v2x.audit_trial_coverage import CoverageError, audit

KEYS = ("world", "candidate", "baseline")
HEX = set("0123456789abcdef")

def _object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise CoverageError("Duplicate manifest key")
        out[key] = value
    return out

def verify(manifest_path, manifest_sha256, world, candidate, baseline):
    if not isinstance(manifest_sha256, str) or len(manifest_sha256) != 64 or any(c not in HEX for c in manifest_sha256):
        raise CoverageError("Expected lowercase SHA-256 manifest pin")
    raw = Path(manifest_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise CoverageError("Manifest differs from out-of-band pin")
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(CoverageError("Nonfinite manifest value")))
    except (UnicodeError, ValueError) as exc:
        raise CoverageError("Invalid manifest JSON") from exc
    if not isinstance(manifest, dict) or set(manifest) != {"protocol", "trial_id", "split", "seed", "inputs"}:
        raise CoverageError("Unexpected manifest schema")
    if manifest["protocol"] != "paired-world-coverage-pin-v1" or manifest["split"] != "held_out":
        raise CoverageError("Wrong protocol or non-held-out split")
    if not isinstance(manifest["trial_id"], str) or not manifest["trial_id"].strip() or manifest["trial_id"].strip() != manifest["trial_id"]:
        raise CoverageError("Invalid trial identity")
    if type(manifest["seed"]) is not int or manifest["seed"] < 0:
        raise CoverageError("Invalid seed")
    pins = manifest["inputs"]
    if not isinstance(pins, dict) or set(pins) != set(KEYS):
        raise CoverageError("Missing input pin")
    paths = dict(world=world, candidate=candidate, baseline=baseline)
    for name in KEYS:
        pin = pins[name]
        if not isinstance(pin, str) or len(pin) != 64 or any(c not in HEX for c in pin):
            raise CoverageError("Invalid input digest")
        if hashlib.sha256(Path(paths[name]).read_bytes()).hexdigest() != pin:
            raise CoverageError("Input digest mismatch: " + name)
    result = audit(world, candidate, baseline)
    if result["world_sha256"] != pins["world"] or any(result["methods"][name]["sha256"] != pins[name] for name in ("candidate", "baseline")):
        raise CoverageError("Input changed during audit")
    return {"protocol": "paired-world-coverage-pinned-v1",
            "manifest_sha256": manifest_sha256, "trial_id": manifest["trial_id"],
            "split": manifest["split"], "seed": manifest["seed"], "audit": result,
            "limitation": "Out-of-band operator pin is not independent timestamping, source authenticity or complete capture attestation"}

def main():
    parser = argparse.ArgumentParser()
    for name in ("manifest", "manifest_sha256", "world", "candidate", "baseline", "output"):
        parser.add_argument("--" + name.replace("_", "-"), required=True)
    args = parser.parse_args()
    report = verify(args.manifest, args.manifest_sha256, args.world, args.candidate, args.baseline)
    Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
