# v2.6 Permissioned Consensus & Identity Admission Hardening

## Purpose

v2.6 moves OmniGuard V2X sync voting from an authenticated-but-turnout-based model to an explicitly enrolled, epoch-scoped permissioned model.

This is research hardening. It is not a proof of Byzantine fault tolerance, a production PKI, or vehicle-safety certification.

## Identity admission

Normal sync admission now requires `SMARTCAR_SYNC_VEHICLE_KEYS_JSON` to contain the connecting identity. Possession of the global sync PSK alone is no longer sufficient.

`SMARTCAR_SYNC_ALLOW_GLOBAL_PSK_ADMISSION=1` exists only as an explicit lab migration mode and weakens the identity boundary.

Missing or invalid `SMARTCAR_IDENTITY_ADMISSION_POLICY` resolves to `DENY_UNCONFIGURED`, not `OPEN_REGISTRATION`. Open registration remains possible only when explicitly selected for controlled experiments, and metadata continues to state that it provides no Sybil-resistance guarantee.

Registry-style policies only report limited identity creation when an actual non-empty enrollment registry is configured. Selecting a policy name by itself does not create a security guarantee.

## Permissioned validator membership

The active validator set is derived from `SMARTCAR_SYNC_VALIDATOR_IDS`, falling back to enrolled PoA authority IDs when the explicit list is empty. Every voting validator must also have an independent signing key in `SMARTCAR_POA_AUTHORITY_REGISTRY_JSON`.

A network session is already bound to an authenticated identity. v2.6 additionally requires the vote's `voter_id` to match that session identity and requires that identity to be in the active validator set.

## Signed vote contract

Every vote is HMAC-SHA256 authenticated with the enrolled validator key and binds:

- consensus domain/version;
- epoch;
- proposal ID;
- 256-bit proposal hash;
- validator identity;
- yes/no decision;
- proposal timestamp.

Changing any bound field invalidates the vote signature.

Session MAC authentication remains in place as a transport/session control; the validator vote signature is a separate consensus-level binding.

## Quorum

Default quorum is 2/3 of the complete configured validator set:

`ceil(validator_count * 2 / 3)`

This fixes the previous behavior where a majority of only the validators who happened to vote could appear to approve a proposal.

Example with three validators:

- 1 yes: pending, not accepted;
- 2 yes: accepted;
- 2 no: rejected because the acceptance quorum is no longer reachable.

The numerator and denominator are configurable, but invalid fractions fail closed.

## Duplicate and equivocation handling

One validator can cast at most one vote for one proposal in one epoch. A repeated vote is rejected rather than overwritten. A yes-to-no or no-to-yes vote flip is therefore also rejected.

Once a proposal becomes `ACCEPTED` or `REJECTED`, its result is frozen and late votes are rejected.

A proposal ID is also bound to one proposal hash and one proposal timestamp for the epoch; attempts to reuse the ID for substituted content are rejected.

## Epochs and validator rotation

Consensus state is epoch-scoped. `rotate_consensus_epoch()` requires a monotonically increasing epoch and a newly validated validator/key mapping. Rotation clears old proposal state so votes from a previous membership epoch cannot be mixed into a new quorum.

This is currently a local administrative reconfiguration boundary. It is **not** a replicated on-chain membership-change protocol and does not claim distributed reconfiguration safety under network partitions.

## Proposal freshness and capacity

Proposal timestamps are checked against `SMARTCAR_CONSENSUS_PROPOSAL_TTL_SEC` (30 seconds by default). Stale/future proposals outside the allowed window fail closed.

The in-memory proposal registry is bounded by `SMARTCAR_CONSENSUS_MAX_PROPOSALS` to avoid unbounded state growth.

## Go control backend boundary

The Go process is a local authenticated control backend, not a consensus participant. v2.6 therefore removes network identity-admission policy from its inherited runtime environment. Normal dashboard-facing identity/consensus metadata is sourced from the Python sync enforcement layer.

This avoids presenting a policy string inside the Go control process as proof that network admission or validator quorum was actually enforced there.

## Threat boundary

Permissioned enrollment materially reduces outsider and Sybil voting risk, but it does **not** make a malicious authorized supermajority harmless. If enough enrolled validators are compromised or collude to reach quorum, they can still approve malicious future proposals without breaking SHA-256/SHA3 or finding a hash collision.

Accordingly, v2.6 continues to report:

- `majority_attack_resistant = false`;
- `protects_against_forward_majority_control = false`.

Future hardening may add certificate-backed enrollment, distributed membership governance, validator revocation proofs, persistent signed consensus journals, threshold signatures, and formally analyzed BFT protocols.

## Validation targets

The security baseline covers:

- outsider validator rejection;
- forged session/voter identity rejection;
- invalid vote signature rejection;
- duplicate vote and vote-flip rejection;
- full-validator-set quorum calculation;
- proposal hash substitution rejection;
- proposal timestamp/freshness rejection;
- wrong-epoch rejection;
- epoch rotation and old-validator rejection;
- finalized-proposal freeze;
- global-PSK-only sync admission rejection;
- metadata redaction;
- all prior sync, DID, V2X, control API, ledger, credential, key-provider, runtime-isolation, and Go build tests.
