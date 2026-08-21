# v2.7 Adversarial Security Validation & Fuzzing

## Status

Research hardening phase. This phase improves repeatable negative testing and
bounded fuzz validation. It is not a penetration-test certification, a formal
proof of security, a vehicle-safety certification, or evidence that the system
is impossible to compromise.

## Goals

v2.7 adds repeatable adversarial regression coverage for the security boundaries
introduced in v2.1-v2.6:

- malformed sync protocol messages;
- authenticated-message MAC tamper and replay handling;
- permissioned-consensus vote mutation and quorum invariants;
- corrupted committed-ledger metadata;
- control API URL/signing contract misuse;
- Go HTTP handler malformed payloads;
- chain persistence path confinement;
- bounded replay-cache behavior under unique-nonce floods.

All default CI campaigns are intentionally bounded and repository-local. They do
not scan public networks or attack third-party systems.

## Deterministic Python campaign runner

`adversarial_validation.py` accepts an explicit seed and iteration count. The
same seed produces the same randomized mutation choices and outcome counts.

Example:

```bash
python adversarial_validation.py \
  --seed 168938023 \
  --iterations 256 \
  --max-duration-sec 20 \
  --output security-reports/adversarial-validation.json
```

The report records:

- campaign name;
- seed;
- executed case count;
- accepted/rejected case counts;
- unexpected failures;
- duration;
- aggregate pass/fail status.

CI uploads the generated JSON report as a short-lived GitHub Actions artifact.

## Static security corpora

Two initial corpora are version controlled:

- `tests/security_corpus/sync_malformed.json`
- `tests/security_corpus/ledger_corruption_cases.json`

The sync corpus contains malformed JSON, type confusion, missing or invalid
message authentication fields, invalid timestamps/nonces, and malformed vote
payloads. The ledger corpus mutates committed identity, linkage, event,
validator, timestamp, telemetry hash, metadata, and consensus-related fields.

Corpus cases are seeds, not an exhaustive threat model. New minimized crash or
logic-regression cases should be added when discovered.

## Go native fuzz targets

`api/go/adversarial_fuzz_test.go` adds Go fuzz targets for:

- malformed emergency-brake JSON;
- unsigned actuator/state mutation attempts;
- chain path confinement;
- health challenge parsing.

Normal `go test` executes the seed corpus. CI also provides each target a short,
bounded fuzz window. This catches panics, server-side 5xx responses caused by
malformed input, path escapes, and rejected payloads that mutate protected state.

## Replay nonce flood hardening

Testing identified that freshness-based replay caches could otherwise grow with
unique authenticated nonces for the entire replay window. v2.7 introduces
`BoundedReplayCache`.

Behavior at capacity is deliberately fail-closed:

1. live nonce entries are not evicted;
2. unknown new nonces are treated as already claimed and rejected;
3. memory does not continue growing beyond the configured capacity;
4. expired entries are still pruned and restore capacity;
5. an attacker cannot force eviction of a live nonce and then replay it within
   the freshness window.

Configuration:

```text
SMARTCAR_SYNC_REPLAY_CACHE_MAX_ENTRIES=4096
SMARTCAR_SYNC_HANDSHAKE_REPLAY_CACHE_MAX_ENTRIES=4096
```

Saturation can temporarily deny new authenticated messages on the affected
session until entries expire. This is an intentional bounded-memory tradeoff and
does not replace upstream rate limiting or per-peer resource quotas.

## CI gate

The Security Baseline workflow now runs:

- Python compile checks;
- all prior credential/key/runtime/sync/DID/V2X/control/ledger/consensus suites;
- replay-flood regression tests;
- deterministic adversarial campaigns;
- Go security tests plus fuzz seed corpus;
- bounded Go fuzz windows;
- Go build;
- adversarial JSON report upload.

Any unexpected adversarial campaign result returns a non-zero exit status.

## Security limitations still open

v2.7 does not provide:

- exhaustive state-space exploration;
- formal verification;
- continuous long-duration fuzz infrastructure;
- kernel/network namespace sandboxing;
- production PKI or hardware-backed validator identity;
- authenticated transport against privileged local OS attackers;
- protection against an authorized malicious validator supermajority;
- fleet-scale DDoS protection or infrastructure rate limiting;
- hardware-in-the-loop fault injection.

Longer fuzz campaigns, sanitizer matrices, HIL fault injection, packet-loss and
latency chaos, resource-exhaustion profiling, and crash-corpus minimization are
appropriate follow-up work.
