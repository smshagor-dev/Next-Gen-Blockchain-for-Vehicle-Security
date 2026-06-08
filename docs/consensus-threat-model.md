# OmniGuard V2X Consensus Threat Model

OmniGuard V2X uses dual SHA2/SHA3 block hashing for audit integrity and
tamper evidence. This is distinct from consensus safety. Dual hash chaining
does not prevent a validator majority from approving malicious but
syntactically valid future blocks.

## What Dual SHA2/SHA3 Chaining Protects

- Tamper evidence for historical block modification.
- Collision resistance against accidental corruption and non-majority
  retroactive rewriting under standard hash assumptions.
- Stronger audit integrity by keeping independent SHA2 and SHA3 hash paths in
  the block record.

## What It Does Not Protect

- Majority validator control.
- Colluding validators with quorum.
- Valid but malicious future blocks approved by the voting majority.
- Governance capture or admission-policy failures.

## Why a 51% Attacker Does Not Need a Hash Collision

A majority adversary can create a fresh block, compute valid SHA2/SHA3 hashes
for that block, and approve it through the normal voting process. No SHA2 or
SHA3 collision is required because the attacker is not trying to make two
different blocks share the same hash. They are using consensus control to make
the malicious block canonical.

## Retroactive Tampering vs Forward Consensus Capture

Retroactive tampering means changing an existing historical block while trying
to preserve the old chain evidence. Dual hash chaining helps detect this.

Forward consensus capture means controlling enough validators to approve the
next block. Dual hash chaining does not stop this because the malicious block
can be internally well-formed and honestly hashed.

## Consensus Metadata

```json
{
  "consensus_model": "simple_majority",
  "majority_attack_resistant": false,
  "dual_hash_chaining": true,
  "retroactive_tamper_evidence": true,
  "protects_against_forward_majority_control": false,
  "notes": "A voting majority can approve syntactically valid malicious blocks without finding hash collisions."
}
```

## Future Mitigation Options

- BFT consensus.
- Stake-weighted slashing.
- Permissioned validator registry.
- Transportation authority enrollment.
- Rotating committees.
- Hardware-backed attestation.
- Anomaly-based governance alerts.

These mitigations are future deployment controls. They are not provided by dual
hash chaining alone.
