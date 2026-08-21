# Security Policy

OmniGuard V2X is a research security platform. It must be treated as a research prototype until the security release gates documented in this repository are satisfied.

## Supported security baseline

Security fixes are developed on dedicated hardening branches and must pass regression tests before they are merged into `main`.

## Reporting a vulnerability

Do not publish exploit details, credentials, private keys, authentication tokens, recovery material, or other sensitive data in a public issue.

Use GitHub private vulnerability reporting / Security Advisories when available for this repository. If private reporting is unavailable, contact the repository maintainer privately and provide:

- affected commit or release;
- impacted component;
- reproduction steps;
- security impact;
- suggested remediation, if known.

## Secret handling

The repository must never contain real runtime secrets. Local `.env` files are ignored. Only `.env.example` with empty or non-sensitive example values may be committed.

Any secret that has previously appeared in Git history must be considered compromised and rotated. Removing a file in a later commit does not remove the historical copy.

## Release security gates

A security-ready release requires, at minimum:

- zero unresolved Critical vulnerabilities;
- zero unresolved High vulnerabilities accepted without a documented risk decision;
- authenticated and authorized mutation/control interfaces;
- replay-resistant V2X and synchronization traffic;
- validated vehicle/validator identity binding;
- complete ledger integrity verification;
- secret scanning and dependency scanning;
- adversarial regression tests;
- signed and reproducible release artifacts where feasible.

No release should be described as "hack-proof".
