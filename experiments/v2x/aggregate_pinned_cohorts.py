"""Aggregate independently pinned V2X paired trial exports; research software only.

One source-group-disjoint scenario/seed is one cluster. Pins and declared group
independence do not prove publisher authenticity or preregistration.
"""
import argparse
import csv
import hashlib
import io
import json
import random
from pathlib import Path

COLUMNS = ["incident_id", "cluster_id", "truth", "baseline", "candidate"]
MAX_BYTES = 16 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate JSON key")
            obj[key] = value
        return obj
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON constant")))


def hex_digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def aggregate(manifest_raw, artifacts, *, external_pin, repetitions=2000, seed=2026):
    if not 100 <= repetitions <= 100000 or type(seed) is not int:
        raise ValueError("invalid bootstrap configuration")
    if len(manifest_raw) > MAX_BYTES or not hex_digest(external_pin) or sha(manifest_raw) != external_pin:
        raise ValueError("manifest external pin mismatch")
    manifest = strict_json(manifest_raw)
    if type(manifest) is not dict or set(manifest) != {"schema_version", "trials"} or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("invalid cohort manifest")
    trials = manifest["trials"]
    if type(trials) is not list or not 2 <= len(trials) <= 1000:
        raise ValueError("at least two trial clusters required")
    if type(artifacts) is not dict or len(artifacts) != len(trials):
        raise ValueError("all and only pinned trial files required")
    seen_trials, seen_clusters, seen_groups = set(), set(), set()
    clusters = []
    counts = {name: {key: 0 for key in ("tp", "tn", "fp", "fn")} for name in ("baseline", "candidate")}
    baseline_only = candidate_only = 0
    for item in trials:
        if type(item) is not dict or set(item) != {"trial_id", "cluster_id", "source_group_id", "paired_csv_sha256"}:
            raise ValueError("invalid trial schema")
        trial, cluster, group, pin = (item[key] for key in ("trial_id", "cluster_id", "source_group_id", "paired_csv_sha256"))
        if any(type(x) is not str or not x or len(x) > 128 for x in (trial, cluster, group)) or not hex_digest(pin):
            raise ValueError("invalid trial identity or digest")
        if trial in seen_trials or cluster in seen_clusters or group in seen_groups:
            raise ValueError("duplicate trial, cluster or source group")
        seen_trials.add(trial)
        seen_clusters.add(cluster)
        seen_groups.add(group)
        raw = artifacts.get(trial)
        if type(raw) is not bytes or len(raw) > MAX_BYTES or sha(raw) != pin:
            raise ValueError("trial CSV missing or tampered")
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
        if reader.fieldnames != COLUMNS:
            raise ValueError("invalid paired CSV schema")
        n = improvement = 0
        incident_ids = set()
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("ragged CSV")
            incident = row["incident_id"]
            if not incident or incident in incident_ids or row["cluster_id"] != cluster:
                raise ValueError("duplicate incident or cluster mismatch")
            incident_ids.add(incident)
            if any(row[key] not in ("0", "1") for key in ("truth", "baseline", "candidate")):
                raise ValueError("nonbinary outcome")
            truth, baseline, candidate = (int(row[key]) for key in ("truth", "baseline", "candidate"))
            for name, value in (("baseline", baseline), ("candidate", candidate)):
                outcome = "tp" if truth and value else "fn" if truth else "fp" if value else "tn"
                counts[name][outcome] += 1
            delta = int(candidate == truth) - int(baseline == truth)
            improvement += delta
            baseline_only += delta == -1
            candidate_only += delta == 1
            n += 1
            if n > 100000:
                raise ValueError("incident bound exceeded")
        if n == 0:
            raise ValueError("empty trial")
        clusters.append((n, improvement))
    total = sum(n for n, _ in clusters)
    estimate = sum(delta for _, delta in clusters) / total
    rng = random.Random(seed)
    draws = []
    for _ in range(repetitions):
        sample = [clusters[rng.randrange(len(clusters))] for _ in clusters]
        draws.append(sum(delta for _, delta in sample) / sum(n for n, _ in sample))
    draws.sort()
    return {"publication_ready": False, "manifest_sha256": external_pin,
            "clusters": len(clusters), "incidents": total, "confusion_counts": counts,
            "candidate_only_correct": candidate_only, "baseline_only_correct": baseline_only,
            "candidate_minus_baseline_accuracy_pp": 100 * estimate,
            "cluster_bootstrap_95pct_percentile_ci_pp": [100 * draws[int(.025 * repetitions)],
                100 * draws[min(repetitions - 1, int(.975 * repetitions))]],
            "bootstrap_seed": seed, "bootstrap_repetitions": repetitions,
            "limitations": ["Source-group independence is asserted, not independently certified.",
                "SHA-256 pin does not prove preregistration or publisher authenticity.",
                "Percentile bootstrap can under-cover with few clusters; no significance claim.",
                "Paired CSVs do not establish hardware safety or sensing uptime."]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--external-manifest-sha256", required=True)
    p.add_argument("--trial-directory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--repetitions", type=int, default=2000)
    a = p.parse_args()
    raw = a.manifest.read_bytes()
    manifest = strict_json(raw)
    trials = manifest.get("trials", []) if isinstance(manifest, dict) else []
    if type(trials) is not list or len(trials) > 1000:
        p.error("invalid trial count")
    artifacts = {}
    for item in trials:
        name = item.get("trial_id") if isinstance(item, dict) else None
        if type(name) is not str or not name or len(name) > 128 or not all(c.isascii() and (c.isalnum() or c in "-_") for c in name):
            p.error("unsafe trial filename")
        path = a.trial_directory / (name + ".csv")
        if path.stat().st_size > MAX_BYTES:
            p.error("oversized trial file")
        artifacts[name] = path.read_bytes()
    result = aggregate(raw, artifacts, external_pin=a.external_manifest_sha256,
                       seed=a.seed, repetitions=a.repetitions)
    if a.output.exists():
        raise FileExistsError("refuse to overwrite evidence")
    a.output.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"report_sha256": sha(a.output.read_bytes()), "publication_ready": False}))


if __name__ == "__main__":
    main()
