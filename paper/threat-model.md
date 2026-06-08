# Threat Model

This manuscript scaffold uses a bounded prototype threat model. The goal is to identify what the implemented system can report and validate today, while separating that from production-grade guarantees that require additional mechanisms and experiments.

## Attacker Capabilities

- Network observation, replay, delay, and message injection attempts within the limits of the prototype transport.
- Malformed or implausible vehicle telemetry inputs, including trivial trigger values and realistic noisy ranges in future datasets.
- Identity misuse attempts against enrolled identities.
- Federated-learning poisoning attempts represented by logged experiment outputs or future configured attacks.
- Validator misbehavior within a simple-majority audit-chain model.
- Attempts to infer hidden committed values from Pedersen commitments.

## Out-Of-Scope Claims

- No claim of end-to-end post-quantum security.
- No Sybil resistance under `OPEN_REGISTRATION`.
- No majority-control resistance under simple-majority consensus.
- No secure aggregation under `COMMIT_ONLY` Pedersen mode.
- No general attack-detection guarantee from single-run sanity checks.
- No fleet-scale runtime scalability claim from communication-volume simulations alone.

## Boundary Statements

Lamport DID metadata supports identity authenticity for a registered identity, but it does not prevent an adversary from creating many identities when registration is open. Sybil resistance requires an external admission policy such as authority enrollment, manufacturer certificates, proof-of-stake, proof-of-work, or another deployment-specific control.

The simple-majority consensus model can record an audit trail and detect some integrity failures, but it does not withstand majority control. If a majority of validators collude or are compromised, forward consensus decisions can be captured.

The default Pedersen mode is `COMMIT_ONLY`. Commitments are verifiable and homomorphically combinable, but aggregate values remain hidden unless valid openings or a separate secure aggregation / zero-knowledge disclosure protocol is implemented.

