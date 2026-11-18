# Research status: authenticated ingress per-frame delivery (2026-11-18)

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| Production TCP/serial per-frame delivery | Implemented; repository validation pending | `hardware_bridge.py` now iterates verified frames so later invalid MAC cannot suppress earlier delivery |
| Authentication, bounded TCP, non-actuating dispatch | Existing main controls retained | No new physical safety guarantee |
| Regression tests | Committed; not executed on checkout | `tests/test_ingress_per_frame_delivery.py` |
| Replay claim versus ledger commit | **Partial / unsafe for exactly-once** | MAC verification claims nonce before ledger push; ledger exception can still lose valid event |
| Framing errors with mixed read | Partial | Framer pre-processes all lines; oversized trailing frame can reject entire read before yield |
| Durable replay and rollback | Partial / blocked | Experimental SQLite gate not integrated; rollback and power loss remain unproven |
| Ledger checkpoint and mock finality | Partial | No distributed finality claim |
| Independent incident admission | Partial | Synthetic scenarios are non-publishable effectiveness evidence |
| Genuine VeReMi/CAN incident ground truth | Blocked | CAM attack labels are not incident labels; independent source needed |
| Matched multi-seed runtime statistics | Upcoming | No publishable uncertainty/effect sizes yet |
| Hardware emergency stop | Blocked | Local physical emergency control must remain independent; no bench verification |
| Scientific paper | Blocked | Genuine independent evidence insufficient |

## Hypothesis and limitations

H1 (availability): For a TCP read containing a valid authenticated telemetry frame followed by a MAC-invalid but correctly framed envelope, eager batch verification consumes the first nonce without delivering it. Streaming verification allows the earlier valid frame to reach ledger processing before rejecting the second. This is a deterministic software contract, **not** a scientific performance result or a safety proof.

H2 (remaining gap): If ledger commit fails after the replay claim, retransmission may still be rejected. Future work must establish explicit durable commit/ack boundaries and crash-injection experiments. Do not silently release nonce claims after ambiguous ledger commits (would risk duplicates).

## Test commands

```sh
python -m unittest discover -s tests -p 'test_ingress_per_frame_delivery.py' -v
python -m unittest discover -s tests -p 'test_ingress_batch_atomicity.py' -v
python -m unittest discover -s tests -v
```

Note: the previous batch negative-control tests deliberately assert the eager `receive()` failure; those tests should remain negative controls. No hardware, external datasets or physical actuation were used. No numeric scientific claims are made.
