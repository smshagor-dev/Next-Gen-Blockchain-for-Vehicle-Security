# OmniGuard V2X research status matrix — deadline guard workstream

Updated: 2026-11-21. This is an incremental matrix; other workstreams and open PRs remain authoritative in their respective tracking files.

| Research/engineering objective | Status | Evidence / limitations |
| --- | --- | --- |
| Reject NaN/infinite monotonic samples and deadlines | Completed (isolated) | Eight local unit tests executed against exact proposed module contents; full checkout not run |
| Reject truthy nonboolean authentication flags | Completed (isolated) | Regression test covers string, integer and null flags |
| Reject malformed deadline ordering | Completed (isolated) | Deadline order regression |
| Validate production TCP/serial caller clock domain and configuration | Partial | Caller source inspected, exact integration suite pending |
| Preserve independent local emergency actuation | Partial | No actuator code modified; physical fail-safe verification blocked |
| Authenticated bounded ingress and replay protection | Partial | Existing production components; full integration/fault injection pending |
| Ledger crash consistency and independent finality | Partial / blocked | Local checkpoint does not prove independent distributed finality |
| Genuine VeReMi NextGen/CAN incident-level evaluation | Partial | CAM labels are not incident ground truth |
| Paired independent attack/fault baselines and uncertainty | Upcoming | No new scientific efficacy results claimed |
| Physical hardware-in-loop safety evidence | Blocked | No lab or vehicle access |

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_hardware_deadline_fail_closed.py' -v
python -m unittest discover -s tests -v
```

The first command passed in an isolated local copy (8/8, 2026-11-21). The second command has not been executed on the exact GitHub checkout. This fix is a bounded software safety guard, not an original cryptographic method or publishable scientific effectiveness result. Next: run exact-checkout integration tests and exercise actual TCP receiver with fragmented frames, deadline expiry, concurrent clients, and emergency control precedence.
