# Pedersen Aggregation Model

OmniGuard V2X uses Pedersen-style commitments in the default `COMMIT_ONLY` mode. Pedersen commitments support additive homomorphism over committed values, but the aggregate remains hidden unless participants provide valid openings or a separate secure aggregation / zero-knowledge disclosure protocol is implemented.

## Active Metadata

```json
{
  "pedersen_mode": "COMMIT_ONLY",
  "commitment_homomorphic": true,
  "aggregate_statistics_recoverable": false,
  "requires_opening_for_aggregate": true,
  "secure_aggregation_implemented": false
}
```

## Modes

### COMMIT_ONLY

- Default active mode.
- Commitments are verifiable but values remain hidden.
- Aggregate statistics are not recoverable from commitments alone.

### AGGREGATE_OPENING

- Participants reveal openings or aggregate opening material.
- The aggregate value can be verified against the combined commitment.
- Privacy is weakened depending on reveal granularity and whether individual or aggregate openings are disclosed.

### SECURE_AGGREGATION_FUTURE

- Placeholder future mode.
- Not implemented.
- The current project must not claim active support for privacy-preserving aggregate-statistics extraction.

## What Pedersen Commitment Hides

A commitment hides the committed value using fresh blinding material. Observers can verify valid proof relations, such as knowledge of an opening or a speed-limit relation, without reading the hidden value.

## What Homomorphic Combination Means

Given commitments to values, multiplying commitments combines the committed values and blinding factors algebraically. This produces a commitment to the sum of the hidden values. It does not reveal the sum.

## Why Aggregate Value Is Not Readable From Commitment Alone

The combined commitment remains hiding. Without an opening for the aggregate value and aggregate blinding factor, observers cannot read mean velocity, average velocity, or other aggregate statistics directly from the commitment.

## When Aggregate Can Be Verified

An aggregate can be verified when participants reveal valid openings or provide aggregate opening material that matches the combined commitment. A separate secure aggregation or zero-knowledge disclosure protocol could also reveal only approved statistics, but that is future work here.

## Privacy Trade-Off Of Revealing Openings

Revealing individual openings exposes individual values. Revealing only aggregate opening material exposes the aggregate and may preserve more individual privacy, but it still reveals information about the group. The privacy impact depends on group size, auxiliary knowledge, and repeated releases.

## Future Secure Aggregation Options

- Add a dedicated secure aggregation protocol for aggregate statistics.
- Add zero-knowledge disclosure proofs for selected aggregate predicates.
- Use threshold disclosure so no single node can reveal individual values.
- Define release policies for minimum group size and rate limiting.
