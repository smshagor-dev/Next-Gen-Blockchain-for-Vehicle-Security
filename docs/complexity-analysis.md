# Complexity Analysis

OmniGuard V2X has component-dependent complexity. The prototype should not be described as a whole-system `O(n)` design because local computation, pairwise sessions, broadcast, vote collection, chain auditing, and FL aggregation scale differently.

## Definitions

- `n`: number of peers, vehicles, validators, or connected nodes in the evaluated communication group.
- `d`: model dimension count for federated-learning update vectors.
- `k`: number of blocks in the blockchain audit range.

## Component-Level Complexity

| Component | Complexity | Scope / condition |
|---|---|---|
| Local vehicle sensing/input validation | `O(1)` | Per vehicle sample when checking a fixed telemetry schema and fixed threshold/rule set. |
| ML-KEM session establishment | `O(1)` per pairwise session; `O(n)` for one node connecting to `n` peers; `O(n^2)` for full mesh | Pairwise cryptographic sessions are constant per pair, but full mesh requires every node pair to connect. |
| Gossip broadcast | `O(n)` per message from one node; `O(n^2)` total network message volume under naive all-to-all gossip | One sender reaches `n` peers; all peers broadcasting in the same round creates quadratic message volume. |
| Simple-majority vote collection | `O(n)` for one proposal; `O(n^2)` if every validator proposes/broadcasts in the same round | One proposal collects one vote from each validator; concurrent proposals multiply traffic. |
| Blockchain hash append / latest-block verify | `O(1)` append; `O(k)` chain audit for `k` blocks | Latest append and hash check are constant, while full audit scans the selected chain range. |
| FL aggregation | `O(n*d)` | Aggregating `n` client updates with `d` model dimensions. |
| Dashboard/API reporting | `O(1)` per status request; `O(n)` if aggregating node states | Local status reads are constant; fleet summaries scale with node count. |

## Why The Old O(n) Claim Was Incomplete

Some operations are linear for a single node or a single proposal, such as broadcasting one message to peers or collecting votes for one proposal. That does not make the whole system `O(n)`. A full mesh of pairwise sessions or naive all-to-all gossip creates `O(n^2)` network message volume. Chain audits depend on `k`, and FL aggregation depends on both `n` and model dimension `d`.

## When O(n^2) Appears

Quadratic behavior appears when every node communicates with every other node in the same round. Examples include full-mesh session establishment, naive all-to-all gossip, and every validator proposing or broadcasting simultaneously. These are network-volume limits, not evidence of a validated large-scale deployment.

## Scalability Limitation

The current prototype is a demonstration stack. It does not include production-grade network topology control or a benchmark proving large fleet scalability. Naive full-mesh communication and all-validator broadcast should be treated as scalability limitations.

## Future Mitigation

- Committee selection.
- Hierarchical gossip.
- Batching.
- Partial aggregation.
- Sharding.
- BFT only with bounded committee size.
