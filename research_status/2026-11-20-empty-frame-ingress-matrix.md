# OmniGuard V2X research validation matrix — 2026-11-20

| Workstream | State | Evidence / next gate |
| --- | --- | --- |
| Hardware TCP empty-line CPU-work bound | Implemented; exact checkout unverified | Commit 4e436fd; cap 256 delimiters per feed including empty frames |
| Empty-line, mixed-frame, fragmentation regressions | Implemented; unexecuted | Commit e788501; run `python -m unittest discover -s tests -p 'test_hardware_empty_frame_cpu_bound.py' -v` |
| Authenticated TCP replay after restart | Partial | Volatile per-process replay cache remains; persistent nonce admission and kill/restart fault injection needed |
| Local emergency control independence | Blocked for physical evidence | Network actuator dispatch intentionally disabled; no physical lab validation |
| Ledger crash consistency and contract finality | Partial / blocked | SQLite transactions are not blockchain finality; require process-kill and independent trust-root analysis |
| VeReMi NextGen / CAN dataset provenance | Pending | Acquire authentic datasets, hashes, licenses, split manifest |
| Matched attack baseline and ablations | Pending | Multi-seed, independent incidents; no fixture or 3-peer results as main evidence |
| CPU/RAM/latency/network scaling | Pending | Isolated processes, controlled hardware, raw measurements and uncertainty |
| Publishable scientific claim ledger | Blocked | No defensible end-to-end effectiveness claims yet |

This change bounds parser work for delimiter floods **per feed call**, not per connection or per second. Repeated calls can still consume CPU; socket read limits, session deadlines and aggregate rate control require separate runtime verification. No tests or physical experiments are claimed as executed in this checkpoint.
