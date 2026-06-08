# Security Assumptions

This scaffold defers detailed technical assumptions to the repository security-boundary documents and summarizes their manuscript implications.

## Referenced Repository Documents

- `docs/security-assumptions.md`
- `docs/identity-security-model.md`
- `docs/consensus-threat-model.md`
- `docs/pedersen-aggregation-model.md`

## Manuscript Framing

OmniGuard V2X should be described as a hybrid-security prototype. ML-KEM/Kyber metadata belongs to the key-establishment path. Pedersen commitments and Schnorr-style proof logic remain classical-assumption components. Lamport identity metadata provides authenticity, not admission control. Simple-majority consensus provides bounded audit behavior, not majority-control resistance. Commit-only Pedersen mode does not reveal aggregate statistics.

Any manuscript statement about security should name the relevant mode, assumption, and limitation rather than presenting a single system-wide guarantee.

