# Original research readiness — 2026-11-23 (GPS boundary run)

| Workstream | State | Evidence / next action |
|---|---|---|
| Signed GPS range gate | Implemented, unverified | `hardware_bridge.py` WGS84 lat/lon bounds; `tests/test_signed_gps_coordinate_bounds.py` |
| Required signed motion/GPS fields | Integrated on main | PR #214; coordinate bounds do not replace required-field enforcement |
| Required obstacle observation | Integrated on main | PR #213 |
| Authenticated ingress and TCP saturation | Partial | Review/integrate PRs #207–#212; execute real handler loopback negatives |
| Local emergency actuation | Blocked hardware validation | Keep remote actuation disabled; independent local emergency circuit |
| Ledger crash consistency and finality | Partial | Crash injection, durable nonce/ledger atomicity, mock-finality limits |
| Authentic VeReMi NextGen/CAN provenance | Blocked | Obtain original recordings, licenses and verified checksums |
| Multi-seed comparative attack evaluation | Upcoming | Identical held-out campaign splits, baselines, uncertainty and effect sizes |
| Publication-grade evidence | Blocked | Fixtures, three-peer sanity checks, five-iteration microbenchmarks and offline formulas excluded |

## Verification and limitations

This change was committed through the GitHub contents API. Exact-checkout tests and full regression were **not executed** in this run. GPS bounds establish coordinate-domain validity, **not** authenticity, localization accuracy, spoofing detection, or sensor trust. The default-zero GPS fallback has been removed by merged PR #214; both explicit field presence and coordinate bounds are enforced. No real vehicle or hardware experiment was performed.

Run after checking out this branch:

```sh
python -m unittest discover -s tests -p 'test_signed_gps_coordinate_bounds.py' -v
python -m unittest discover -s tests -v
```

## Mainline reconciliation (2026-11-24)
Preserved required signed GPS fields and obstacle validation from #214 and #213. Added conversion-level boundary checks and updated the AST-isolated numeric test dependency list. Exact-head CI required; range validation does not demonstrate GPS authenticity or spoofing detection.
