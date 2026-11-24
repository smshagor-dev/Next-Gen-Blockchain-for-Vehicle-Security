# Serial fault-sequence research status (2026-11-21)

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| Synthetic serial fault-sequence state machine | Implemented, unverified in exact checkout | `research_contracts/serial_fault_sequence_model.py`; reference only |
| Nine adversarial regression tests | Written, execution pending | `python -m unittest discover -s tests -p 'test_serial_fault_sequence_model.py' -v` |
| Reproducible six-scenario JSONL protocol | Implemented, execution pending | `python -m research_contracts.serial_fault_sequence_model --seed 17 --sequences 600 --output /tmp/serial_faults.jsonl` |
| Existing hardware serial quarantine and budgets | Partial | Draft PRs #175 and #176; integration not established |
| Physical emergency stop and receiver interlocks | Blocked | No hardware access or physical evidence |
| Independent ledger finality and crash consistency | Partial / blocked | No trusted independent authority |
| Authentic VeReMi NextGen and CAN data | Pending | No verified original dataset provenance in this run |
| Incident-level baselines and multi-seed uncertainty | Pending | Synthetic reference cases are NOT effectiveness results |
| Publication-ready claims | Blocked | No authentic incident-level validation |

**Safety scope:** no ECU, CAN, serial or TCP output is performed by this model. A quarantined state is absorbing. A successful authenticated frame yields evidence only, not actuation. This deliberately does not model cryptographic verification or production transport.

**Next:** validate exact checkout; connect controlled fault injection to the actual serial reader under a mocked transport, without touching local emergency control. Compare baseline and modified bridge under identical adversarial byte sequences.
