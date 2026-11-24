"""Audit held-out artifact bytes and generate reproducible publication tables and figures.

This verifies internal consistency, not an external attestation or population inference.
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
from collections import Counter
from pathlib import Path

from experiments.claim_validation.heldout_runner import (
    ROOT, SCHEDULE, FROZEN, CANDIDATE, SCHEDULE_COMMIT, COUNTS, load_schedule,
    digest, adjudicate, summarize,
)
from experiments.claim_validation.runtime_evidence import canonical
import hashlib

METHODS = ("posture_proxy", "declared_proxy", "gate")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_domain(directory, domain, cases, revision):
    report = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    trace = directory / "trials.jsonl"
    require(report["domain"] == domain and report["executed_sha"] == revision, "execution revision mismatch")
    require(report["candidate_commit"] == CANDIDATE and report["schedule_commit"] == SCHEDULE_COMMIT
            and report["frozen_git_blobs"] == FROZEN, "frozen provenance mismatch")
    require(report["schedule_sha256"] == digest(ROOT / SCHEDULE), "schedule digest mismatch")
    for field, file in (("runner_sha256", "heldout_runner.py"), ("worker_sha256", "heldout_worker.py")):
        require(report[field] == digest(Path(__file__).with_name(file)), "execution source hash mismatch")
    require(report["trace_sha256"] == digest(trace), "trace digest mismatch")
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    expected = {c["id"]: c for c in cases if c["domain"] == domain}
    require(len(rows) == len(expected) == report["scheduled"] == COUNTS[domain], "row count mismatch")
    require({r["id"] for r in rows} == set(expected), "trial allocation mismatch")
    require(dict(Counter(r["status"] for r in rows)) == report["statuses"], "status mismatch")
    require(all(r["status"] == "ok" for r in rows), "non-successful trial retained; publication blocked")
    scopes = set()
    for row in rows:
        case = expected[row["id"]]
        require(row["domain"] == domain and row["cell"] == case["cell"] and row["replicate"] == case["replicate"]
                and row["reference_supported"] is case["expected"], "trial label mismatch")
        o = row["output"]
        require(adjudicate(case, o["direct"]), "reference disagreement")
        record = dict(o["observation"])
        sha = record.pop("sha256")
        require(hashlib.sha256(canonical(record)).hexdigest() == sha, "observation digest mismatch")
        require(record["scope"] == o["expected_scope"] and record["scope"] not in scopes, "scope mismatch")
        scopes.add(record["scope"])
        require(o["gate"]["eligibility"] in {"ELIGIBLE", "NOT_SUPPORTED", "WITHHELD"}, "invalid decision")
        require(type(o["posture_proxy"]) is bool and type(o["declared_proxy"]) is bool, "invalid comparator")
    require(summarize(rows) == report["cells"], "reported cell totals mismatch")
    return rows


def table(domain, rows):
    positive = sum(r["reference_supported"] for r in rows)
    negative = len(rows) - positive
    records = []
    for method in METHODS:
        def eligible(row):
            value = row["output"][method]
            return value["eligibility"] == "ELIGIBLE" if method == "gate" else value is True
        good = sum(r["reference_supported"] and eligible(r) for r in rows)
        bad = sum(not r["reference_supported"] and eligible(r) for r in rows)
        records.append({"domain": domain, "method": method, "n": len(rows), "positive": positive,
                        "negative": negative, "supported_eligible": good, "unsupported_eligible": bad,
                        "supported_rate": good/positive if positive else None,
                        "unsupported_rate": bad/negative if negative else None,
                        "coverage": (good+bad)/len(rows)})
    return records


def locate(root, domain):
    hits = [p.parent for p in root.rglob("summary.json")
            if json.loads(p.read_text(encoding="utf-8")).get("domain") == domain
            and (p.parent / "trials.jsonl").is_file()]
    require(len(hits) == 1, "expected exactly one held-out artifact for " + domain)
    return hits[0]


def figure(records, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    labels = {"posture_proxy": "Posture proxy", "declared_proxy": "Declared capability", "gate": "Evidence gate"}
    fig, axes = plt.subplots(1, 2, figsize=(9.4, 4.0), sharey=True, layout="constrained")
    domains = tuple(COUNTS)
    for ax, rate, numerator, denominator, title in (
        (axes[0], "unsupported_rate", "unsupported_eligible", "negative", "A. Unsupported eligibility"),
        (axes[1], "supported_rate", "supported_eligible", "positive", "B. Supported eligibility"),
    ):
        for i, method in enumerate(METHODS):
            subset = [next(r for r in records if r["domain"] == d and r["method"] == method) for d in domains]
            positions = [j+(i-1)*.23 for j in range(len(domains))]
            bars = ax.bar(positions, [100*r[rate] for r in subset], width=.21, label=labels[method],
                          color=("#767676", "#c28b42", "#246b9b")[i],
                          edgecolor="black", linewidth=.4, hatch=("", "//", "..")[i])
            ax.bar_label(bars, labels=[f"{r[numerator]}/{r[denominator]}" for r in subset], fontsize=7, padding=3)
        ax.set_xticks(range(len(domains)), [d.upper() if d == "pqc" else d.capitalize() for d in domains])
        ax.set_ylim(0, 119)
        ax.set_yticks([0, 25, 50, 75, 100])
        ax.set_title(title, loc="left", fontsize=11)
        ax.grid(axis="y", alpha=.2)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("Eligible trials (%)")
    handles, names = axes[0].get_legend_handles_labels()
    fig.legend(handles, names, loc="outside lower center", ncols=3, frameon=False, fontsize=9)
    fig.savefig(out/"heldout-eligibility.svg", bbox_inches="tight")
    fig.savefig(out/"heldout-eligibility.png", dpi=600, bbox_inches="tight")
    plt.close(fig)


def run(root, out):
    cases = load_schedule()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    records, provenance = [], {}
    for domain in COUNTS:
        directory = locate(root, domain)
        rows = verify_domain(directory, domain, cases, revision)
        records.extend(table(domain, rows))
        provenance[domain] = {n: digest(directory/n) for n in ("summary.json", "trials.jsonl")}
    out.mkdir(parents=True, exist_ok=False)
    csv_path = out/"heldout-eligibility.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    figure(records, out)
    report = {"executed_sha": revision, "audit_source_sha256": digest(Path(__file__)),
              "candidate_commit": CANDIDATE, "schedule_commit": SCHEDULE_COMMIT,
              "verified_trials": sum(COUNTS.values()), "artifact_input_sha256": provenance,
              "outputs_sha256": {n: digest(out/n) for n in ("heldout-eligibility.csv",
                                    "heldout-eligibility.svg", "heldout-eligibility.png")},
              "results": records, "statistical_inference": False,
              "scope": "finite software design; internal artifact consistency only"}
    (out/"audit.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.input, args.out)
