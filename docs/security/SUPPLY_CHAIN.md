# v3.0.3 Supply-Chain Validation Boundary

OmniGuard V2X v3.0.3 generates source and build evidence intended to improve reproducibility and reviewability. It is not a SLSA certification or a guarantee that the build environment is uncompromised.

## Repository controls

- liboqs source fetch is pinned to an exact commit.
- nlohmann/json fallback archive is SHA-256 pinned.
- unsafe fast-math, host-native optimization and IPO remain opt-in.
- CI may enforce the hosted GCC 13.3.x validation toolchain family.
- real liboqs is mandatory for the supported native target.
- the historical simulated-PQC/XOR C++ demo build path is removed.

## Generated evidence

- `release-integrity-manifest.json`: exact commit and tracked-file SHA-256 evidence.
- `sbom-v3.0.3.cdx.json`: deterministic repository-declared direct dependency inventory.
- `provenance-v3.0.3.json`: exact commit/tree and observed validation toolchain metadata.
- `SHA256SUMS`: publication-payload checksums.
- adversarial/HIL/incident reports.

The SBOM explicitly does not claim complete transitive inventory for system packages outside the repository's dependency declarations.

## Current-tree secret scan

`scripts/secret_scan.py` rejects:

- tracked `.env` and non-example `.env.*` files;
- tracked PEM/key/P12/PFX containers;
- private-key PEM markers;
- prohibited known legacy default-secret declarations.

It intentionally does not print suspected secret values.

Git-history scanning and credential rotation are separate owner-controlled operations; see `HISTORY_REMEDIATION.md`.

## External repository settings

Branch protection, required-check policy, GitHub secret-scanning features and private vulnerability reporting are repository/account settings. Source code can document and test workflow expectations but cannot truthfully claim those settings are active without separately verifying them in GitHub.
