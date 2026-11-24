# Reproduce the cross-layer security claim-validity software experiments

This archive is for author review before DOI deposition. It contains a scoped
source snapshot (not the full application or Git history), same-run raw
experimental traces, derived analyses, figures and recorded dependencies.
MANIFEST.json maps SHA-256 hashes to archive members and identifies the
original executed revision. Verify archive.sha256 outside the ZIP and the
member hashes after extraction. The observations use ephemeral laboratory
credentials; no network or physical vehicle execution is claimed.

## Reproduce

Use Linux, Git, Python 3.12, CMake and a C compiler. Review the included
workflow for provider build settings. Use separate fresh output directories.
For exact original checkout, obtain the executed commit from the repository
if accessible. Otherwise, initialize Git in the included source directory
and commit the unmodified snapshot; new run provenance will correctly differ
from the original revision. Do not edit the frozen schedule or candidate.
The archived source is a subset, not a full project build.

Build native liboqs at commit 5a1a854b0dc9f2141bdc771c555ee60c37950183
with shared libraries, OQS_BUILD_ONLY_LIB=ON and
OQS_MINIMAL_BUILD=KEM_ml_kem_512;SIG_ml_dsa_44. Set OQS_INSTALL_PATH and
LD_LIBRARY_PATH to the install prefix and library directory respectively.
Install numpy==1.26.4, liboqs-python==0.16.0.2, cryptography==46.0.5,
matplotlib==3.10.0. See evidence/claim-validity-environment-* for actual
per-job package versions; the workflow uses separate local, PQC and audit jobs.

Run from source/:

```sh
python -m unittest discover -s tests -p 'test_claim_validation_*.py' -v
for domain in consensus identity pqc; do
  python -m experiments.claim_validation.${domain}_probe --out results/$domain
  python -m experiments.claim_validation.paired_comparison --domain $domain --source results/$domain --out results/comparison-$domain
  python -m experiments.claim_validation.design_analysis --domain $domain --source results/$domain --out results/design-$domain
  python -m experiments.claim_validation.performance_probe --domain $domain --source results/$domain --out results/performance-$domain
  python -m experiments.claim_validation.heldout_runner --domain $domain --out results/heldout-$domain
done
python -m experiments.claim_validation.publication_audit --input results --out results/publication
```

The audit of a new run uses its own checkout SHA. Original archive hashes
are expected to differ from fresh runs due to random ephemeral values,
timestamps and timing variability; compare categorical counts and design
allocations, not byte-identical new traces. Preserve failures. No
population inference, field validation or formal security guarantee.

## DOI deposition checklist

Select one completed archive run; verify all members, public disclosure
and data licensing with authors. Deposit the ZIP, archive.sha256 and
MANIFEST.json as a versioned Zenodo software record (subject to author
approval). Confirm contributor names, ORCID, title, license and description
before publication. Source LICENSE is MIT; confirm the evidence license
separately. No DOI has been assigned by this package.

Use the actual published version DOI in both manuscript and submission
portal. Never put a placeholder DOI in a submitted manuscript. Preserve
the exact archived run; do not combine its files with other runs.
