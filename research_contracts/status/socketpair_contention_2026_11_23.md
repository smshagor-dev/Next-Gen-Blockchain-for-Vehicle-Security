# TCP admission contention research status — 2026-11-23

| Workstream | Status | Evidence / remaining gap |
| --- | --- | --- |
| Socketpair saturation and recovery | Partial | Executable campaign and 3 unit tests; local adapted-source smoke tests passed, exact checkout unverified |
| Authenticated Pi ingress | Partial | MAC and durable nonce logic in main; integration attack campaign and full tests outstanding |
| Hardware emergency actuation isolation | Partial | Network-originated actuation disabled in main; independent physical bench verification absent |
| Ledger crash consistency and finality | Partial | Surrogate work is not chain finality evidence; durable recovery pending |
| Genuine VeReMi NextGen / CAN provenance | Blocked | No independently acquired, source-pinned recording verified |
| Independent incident-level baselines | Upcoming | No publishable comparative effect sizes |
| Paper | Blocked | Do not cite fixture CSV, 3-peer sanity checks, five-iteration microbenchmarks or formulas as effectiveness evidence |

## Local verification (limited)
A matching copy of main's BoundedTCPAdmission was used in an isolated local smoke run because github.com DNS failed. Three focused unittest cases passed. Three repeated socketpair trials with two occupied slots and 16 attempts rejected 14 surplus connections per trial, recovered slots, and recorded rejection-batch durations of 0.719765, 0.123461, and 0.147917 ms (median 0.147917 ms). These are environment-specific control measurements, not production throughput or V2X efficacy.

## Next
Run exact-checkout focused/full tests, measure real loopback TCP with authenticated envelopes and attack controls, preserve emergency stop independence, then investigate ledger replay claim / commit atomicity. No hardware access assumed.
