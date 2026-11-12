# Paired baseline evidence protocol (exploratory tooling)

This document is a **protocol proposal**, not evidence of V2X robustness,
scientific novelty, real-world vehicle safety, or publishable results.

## Falsifiable comparison

For each dataset release, fixed held-out split, attack configuration,
network size and adversary fraction, compare a new **evidence-gated,
safety-isolated V2X event admission policy** against a pre-specified baseline.
Do not invent a favorable baseline; compare against authentication-only,
detection-only and a relevant published trust-policy method using identical
message sequences, admission budgets, attack conditions and seeds.

The candidate mechanism must be formally specified and implemented before
claiming novelty. The analyzer introduced here measures *paired outcome
differences*; it is not that candidate mechanism.

## Required raw CSV

Column order is flexible; all columns must be present:

- experiment_id: immutable experiment protocol identifier
- dataset_id / dataset_version: originating dataset and exact release
- split_id: fixed train/test partition identifier
- attack_type: replay, spoofing, stale timing, gradual telemetry drift, etc.
- node_count: number of simulated participants (>0)
- adversarial_fraction: modeled attacker fraction between 0 and 1
- seed: independently executed trial index, not a duplicated row counter
- method: candidate or named baseline
- run_id: traceable upstream run identifier
- metric: e.g. false acceptance rate, F1, latency_ms, safe availability
- value: measured finite numeric value

The two methods must have identical scenario+seed sets. Each combination of
scenario+method+seed+metric must occur once. Missing pairs, repeated seeds
within a scenario/method and NaN/Infinity fail closed.

## CLI

Use only real, verifiable trial logs and put generated reports outside the
source tree until provenance has been independently reviewed.

    python -m experiments.statistics.paired_baseline \
      --input-csv /path/to/verified-trials.csv \
      --output-dir /path/to/evidence-output \
      --candidate evidence-gated \
      --baseline authentication-only \
      --metric false_acceptance_rate \
      --direction lower \
      --min-pairs 30 \
      --bootstrap-draws 5000 \
      --permutations 9999 \
      --seed 1729 \
      --provenance-manifest /path/to/source-manifest.json

Provenance JSON requires raw_csv_sha256, dataset_source, dataset_version,
license, split_protocol, experiment_protocol and source_commit. The hash is
verified against the exact raw CSV bytes; the other metadata remain
*self-reported*, not verified from the external dataset publisher.

Outputs: paired_results.csv, paired_results.json, paired_report.md and
paired_manifest.json (including SHA-256 hashes).

## Analysis, assumptions and claim gates

- Positive improvement is beneficial in the predeclared metric direction.
- The confidence interval is a paired percentile bootstrap of independent
  trial-level differences, not a bootstrap of individual messages.
- The hypothesis test is a two-sided paired sign-flip randomization test:
  exact for up to 16 pairs, Monte Carlo otherwise. Its null assumption is
  sign exchangeability of paired differences. It does not apply blindly to
  time-correlated or dependent trials.
- Multiple tested scenarios within a *single invocation* receive Holm
  correction; tests across different metrics, runs or manuscripts require an
  additional multiplicity plan.
- Paired effect size dz is undefined when paired variance is zero. Its
  magnitude is not proof of external validity.
- If fewer than min-pairs complete matched trials exist, no CI or p-value
  is computed. Default min-pairs is 10 for software checks, but the study
  should pre-register a justified trial count/power or precision target.
- No significance flag is set automatically, even if an exploratory p-value
  is small. A confirmatory study needs frozen hypotheses, valid assumptions,
  run independence, held-out partitions and independent data provenance.
- Failure cases, neutral or negative effects, baseline overhead and latency
  variance must be reported alongside potential improvements.
- All output is explicitly publication_ready=false. Successful synthetic
  regression tests are **not** empirical validation.

## Next evidence milestones

1. Freeze and implement the proposed V2X admission decision state machine,
   with separate local safety fallback and formal invariants.
2. Obtain and verify actual dataset licenses, download provenance, hashes,
   attack labels and held-out splits. No synthetic fixture may be cited.
3. Run paired baseline/ablation campaigns across several attack strengths,
   network faults, message loads and independent trial seeds.
4. Validate independence assumptions, exact trial provenance and comparable
   hardware/runtime conditions. Use raw traces to verify outcome definitions.
5. Preregister effect directions, test families, uncertainty method, stop
   conditions and safety/availability thresholds before final confirmatory
   evaluation; archive immutable manifests and reference source revisions.
