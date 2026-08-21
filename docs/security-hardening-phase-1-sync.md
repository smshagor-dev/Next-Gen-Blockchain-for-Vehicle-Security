# Phase 1 — Sync Trust Hardening

This hardening increment moves the vehicle-to-sync-node path from permissive trust to fail-closed authenticated sessions.

## Security properties added

- `SMARTCAR_SYNC_SHARED_KEY` is mandatory and must be at least 32 characters.
- The previous hard-coded sync secret is rejected explicitly.
- Handshakes are authenticated with HMAC-SHA256 before a session is created.
- A 128-bit random nonce is generated for every protocol message.
- Authenticated messages require a valid MAC; a missing MAC is no longer accepted.
- Authenticated messages must be inside the configured timestamp window.
- Nonces are cached during the replay window and duplicate messages are rejected.
- Once authenticated, a connection is bound to one vehicle identity.
- Payloads cannot claim a different vehicle identity than the session.
- Optional `SMARTCAR_SYNC_VEHICLE_KEYS_JSON` enables per-vehicle credentials; when configured, unknown vehicles fail closed.
- Consensus votes are bound to the authenticated identity instead of trusting payload `voter_id`.
- Vote submission is restricted to `SMARTCAR_SYNC_VALIDATOR_IDS` or configured PoA authority IDs.
- Invalid chain snapshots never replace server state.
- Genesis is validated instead of being skipped by the chain loop.
- Event hashes and block hashes are recomputed during sync validation.
- Incremental block updates are validated before being accepted.
- Message and chain-size limits reduce memory-amplification risk.

## New configuration

```dotenv
SMARTCAR_SYNC_SHARED_KEY=<high-entropy-secret>
SMARTCAR_SYNC_REPLAY_WINDOW_SEC=15
SMARTCAR_SYNC_MAX_CHAIN_BLOCKS=10000
SMARTCAR_SYNC_VEHICLE_KEYS_JSON={}
SMARTCAR_SYNC_VALIDATOR_IDS=
SMARTCAR_POA_AUTHORITY_REGISTRY_JSON={}
```

For stronger vehicle identity separation, configure one independent secret per vehicle using `SMARTCAR_SYNC_VEHICLE_KEYS_JSON`. A global shared key remains available for controlled compatibility/testing, but it does not provide the same isolation as per-vehicle credentials.

## Regression coverage

`tests/test_sync_protocol_security.py` covers:

1. missing MAC rejection;
2. valid MAC acceptance;
3. nonce replay rejection;
4. stale message rejection;
5. authenticated handshake;
6. handshake replay rejection;
7. unknown vehicle rejection with a per-vehicle registry;
8. invalid-chain state-poisoning prevention;
9. genesis validation;
10. session vehicle spoofing rejection;
11. forged voter identity rejection;
12. non-validator vote rejection.

## Remaining Phase 1 work

The sync channel is now substantially stronger, but the branch is not yet production/safety ready. Remaining work includes:

- bind V2X sender IDs to enrolled cryptographic identities;
- remove V2X hard-coded/default shared secrets;
- enforce replay protection on V2X traffic;
- replace reusable Lamport OTS behavior with safe key lifecycle / standardized PQ signatures;
- harden Go control APIs with authentication, authorization, method enforcement, request limits, and process trust;
- rotate and purge every historically committed credential;
- enable protected-branch required checks after CI is green.
