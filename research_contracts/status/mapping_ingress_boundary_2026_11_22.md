# Research status: bounded programmatic hardware ingress (2026-11-22)

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Mapping size and recursion guard | Implemented; unverified | Direct Python mapping now canonicalized and bounded before schema/MAC verification |
| Regression tests | Implemented; execution pending | Three tests for oversized, deeply nested and ordinary invalid mappings |
| Wire JSON nesting guard | Partial | Separate draft PR #201; avoid overlapping implementation |
| Authenticated TCP/serial ingress | Partial | Integration regression suite required |
| Local emergency control | Blocked for physical verification | No hardware or safety-case validation |
| Atomic inbox / ledger idempotency | Partial | Draft PRs #197 and #199; no production finality evidence |
| Authentic incident ground truth | Blocked | VeReMi CAM attacker labels are not independent incident truth |
| Paired multi-seed effectiveness evaluation | Upcoming | No publishable incident-level results |
| Original research article | Not ready | No justified empirical claims |

Run: `python -m unittest discover -s tests -p 'test_mapping_ingress_boundary.py' -v`; then full test suite. Exact committed checkout execution not yet confirmed. These are engineering safety-contract tests, not research effectiveness measurements.
