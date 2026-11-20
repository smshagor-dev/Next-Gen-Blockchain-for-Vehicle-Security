# Hardware replay validation matrix (2026-11-20)

Scope: draft PR #160, opt-in local SQLite nonce store. No physical actuation, independent dataset effectiveness, or finality claim.

| Requirement | Status | Evidence / next check |
| --- | --- | --- |
| Atomic nonce claim before admission | Implemented, unverified | SQLite BEGIN IMMEDIATE / COMMIT; execute exact checkout tests |
| Restart duplicate rejection | Test implemented, unexecuted | tests/test_durable_hardware_replay.py |
| Backwards wall-clock step | Implemented, unverified | Persisted high-water mark in same transaction; restart regression added |
| Invalid bounds fail closed | Implemented, unverified | Boolean/zero/fractional limits and windows rejected |
| Independent-process contention | Tests committed, unexecuted | tests/test_durable_nonce_process_faults.py; exact checkout required |
| Pre-COMMIT abrupt exit | Test committed, unexecuted | tests/test_nonce_transaction_boundaries.py; rollback expected |\n| During-COMMIT power loss | Blocked | Requires controlled power-cut/storage fault harness; no durability claim |\n| Post-COMMIT abrupt exit | Test committed, unexecuted | tests/test_durable_nonce_process_faults.py |\n| Clock sampling under SQLite contention | Fix committed, unverified | Sample time after BEGIN IMMEDIATE; deterministic lock-order regression |
| Trusted host database rollback | Blocked | SQLite state may be restored; requires independent monotonic anchor |
| Clock forward jump | Partial | Can prematurely expire nonce; bounded authenticated timestamp validation helps but trusted time remains an assumption |
| Local emergency stop independence | Blocked | Hardware-level interlock not validated |
| VeReMi NextGen / CAN authentic cohorts | Upcoming | Source license, hash, split and attack protocol needed |
| Matched adversarial baselines and ablations | Upcoming | No publishable measured effectiveness |
| Network/CPU/RAM multi-seed experiments | Upcoming | No validated measured results |

Run from repository root:

```bash
python -m unittest discover -s tests -p 'test_durable_hardware_replay.py' -v
python -m unittest discover -s tests -p 'test_nonce_transaction_boundaries.py' -v\npython -m unittest discover -s tests -p 'test_durable_nonce_process_faults.py' -v\npython -m unittest discover -s tests -v
```

The SQLite high-water mark detects backward wall-clock changes only while its database remains trusted and intact. It is not trusted time, rollback resistance, distributed consensus, or proof of vehicle safety. Existing fixture CSVs, three-peer poisoning checks, five-iteration microbenchmarks and offline communication formulas are excluded from main-paper evidence.
