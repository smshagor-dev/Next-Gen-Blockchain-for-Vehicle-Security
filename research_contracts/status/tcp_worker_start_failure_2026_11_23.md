# Worker-start failure research status — 2026-11-23

| Workstream | Status | Evidence and limitation |
| --- | --- | --- |
| Worker start failure cleanup | Implemented, pending execution | `bounded_tcp_admission.py` releases semaphore, resets active, records rejection, closes socket |
| Injected thread-start failure | Test written, unverified | `tests/test_tcp_worker_start_failure.py` asserts recovery on a second socketpair |
| Close failure on cleanup | Test written, unverified | Injected `OSError` from close must not terminate listener |
| Process interrupt propagation | Test written, unverified | `KeyboardInterrupt` is not silently swallowed |
| Prior rejection close failure | Partial / overlapping draft | PR #208 separately addresses saturated-peer close failures; review integration |
| Authentication, nonce replay, MAC | Partial | Must verify integrated Pi ingress in a real loopback campaign |
| Independent physical emergency control | Blocked for hardware validation | No physical interlock or vehicle access claimed |
| Ledger crash consistency/finality | Partial | Mock finality cannot be presented as blockchain finality |
| Authentic VeReMi NextGen / CAN data | Blocked | No independently verified source release ingest |
| Original research article results | Upcoming | No publishable effectiveness or statistical claim from these regression tests |

## Verification gate
- `python -m unittest discover -s tests -p 'test_tcp_worker_start_failure.py' -v`
- `python -m unittest discover -s tests -p 'test_bounded_tcp_admission.py' -v`
- `python -m unittest discover -s tests -v`

Exact GitHub checkout execution not performed in this run. This is an ingress robustness fix and negative control, **not** a publication-grade research result. Review overlap with #207–#211 and keep draft until tests pass.
