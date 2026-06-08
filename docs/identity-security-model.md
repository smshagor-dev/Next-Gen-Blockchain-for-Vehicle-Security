# OmniGuard V2X Identity Security Model

OmniGuard V2X supports authentic identities through Lamport DID challenge
proofs. This means a verifier can check that a message or proof was produced
by an entity that controls the corresponding signing secrets.

It does not mean that the system is Sybil-resistant under open registration.
A Lamport DID is cheap to create; it does not require stake, proof-of-work,
certificate enrollment, manufacturer enrollment, or transportation authority
approval.

## Identity Authenticity

Identity authenticity means:

- the entity owns the corresponding secret key material;
- signatures or challenge proofs verify against the DID document;
- actions can be attributed to that DID for non-repudiation within the system.

Lamport DID provides cryptographic identity authenticity.

## Non-Repudiation

A valid Lamport proof binds a challenge response to a DID document. Within the
prototype, this supports non-repudiation for signed protocol events. It does
not prove that the DID belongs to a real-world vehicle unless an external
admission policy binds the DID to that vehicle.

## DID Ownership

DID ownership is demonstrated by producing valid Lamport one-time signature
material for a challenge. DID ownership is not an admission-control mechanism.
It does not make identity generation expensive.

## Sybil Attack Definition

A Sybil attack occurs when one adversary creates many identities and uses them
to gain disproportionate influence in voting, consensus, reputation, or network
policy.

## Identity Admission Policy

Supported policy labels:

- `OPEN_REGISTRATION`
- `PROOF_OF_STAKE`
- `PROOF_OF_WORK`
- `CERTIFICATE_AUTHORITY`
- `VEHICLE_MANUFACTURER_REGISTRY`
- `TRANSPORT_AUTHORITY_REGISTRY`

Default policy:

- `OPEN_REGISTRATION`

Under `OPEN_REGISTRATION`, OmniGuard V2X reports:

> No Sybil-resistance guarantee. Unlimited identities may be created.

## Limitations

The system guarantees identity authenticity but not Sybil resistance under open
registration. Lamport hashing, SHA3 preimage hardness, and DID document
generation do not prevent an adversary from creating many identities.

## Deployment Assumptions

A future deployment may achieve Sybil resistance by integrating proof-of-stake,
proof-of-work, certificate authorities, vehicle manufacturer registries, or
transportation authority controlled enrollment. Those controls are external
admission policies and are not provided by Lamport DID alone.
