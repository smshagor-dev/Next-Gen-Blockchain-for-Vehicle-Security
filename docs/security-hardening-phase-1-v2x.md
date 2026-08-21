# Phase 1 — V2X Zero-Trust Transport Hardening

This increment hardens the V2X hub/node trust boundary. A cryptographically valid packet is no longer enough by itself: the sender identity must first be authenticated and bound to the connection/session that produced the packet.

## Security properties added

- Remove the built-in V2X shared-secret default.
- Require high-entropy node credentials.
- Prefer an explicit per-node hub trust store via `SMARTCAR_V2X_NODE_KEYS_JSON`.
- Disable one-global-PSK compatibility by default (`SMARTCAR_V2X_ALLOW_GLOBAL_PSK=0`).
- Authenticate HELLO before creating a session.
- Bind HELLO to node ID, timestamp, and a cryptographically random 128-bit nonce.
- Reject HELLO replay and unknown node IDs.
- Authenticate HELLO_ACK and bind it back to the requested node ID.
- Pin the session's announced signing scheme/public key inside the authenticated HELLO.
- Reject a data-plane packet when its `sender_id` differs from the authenticated connection identity.
- Require established-session authentication for every data-plane message, including PING.
- Bind message authentication to the negotiated session ID.
- Add timestamp-window and per-session nonce replay protection.
- Fix the previous no-KEM/no-ECDH bootstrap mismatch by deriving the same explicit PSK session on both endpoints.
- Keep classical ECDH disabled unless explicitly enabled.
- Add a 1 MiB receive-buffer/message ceiling.
- Re-authenticate each hub-forwarded message separately for its recipient.
- Require recipients to verify the hub forwarding envelope before invoking the application callback.
- Detect forwarded-message tampering and replay.

## Trust model

Recommended deployment separates secrets by role:

- Hub: keeps the complete node-ID -> node-secret registry.
- Vehicle/infrastructure node: keeps only its own `SMARTCAR_V2X_NODE_SECRET`.
- Global PSK mode: migration/testing only; disabled by default because any holder can impersonate any node.

The authenticated HELLO also pins the ephemeral/session signing identity. This means a packet carrying a mathematically valid Dilithium/ECDSA signature cannot simply claim another enrolled `sender_id`; its key was introduced inside the authenticated node session.

## Hub forwarding boundary

The hub verifies the original sender before forwarding. Each recipient then receives a separate `hub_security` HMAC envelope bound to its own session. The recipient rejects the packet before application delivery if that forwarding envelope is missing, stale, replayed, or invalid.

This provides authenticated hub-mediated delivery. It is not claimed as direct sender-to-recipient end-to-end non-repudiation; that is a later protocol milestone requiring a persistent certificate/DID public-key registry and end-to-end signature policy.

## Regression coverage

`tests/test_v2x_security.py` validates:

1. cryptographically random 128-bit nonces;
2. weak/short secret rejection;
3. consistent PSK fallback session derivation;
4. sender/session binding;
5. data-plane replay rejection;
6. stale-message rejection;
7. authenticated hub forwarding;
8. forwarded-message replay and tamper rejection;
9. authenticated HELLO and HELLO replay rejection;
10. unknown-node rejection;
11. HELLO_ACK node binding.

Focused isolated validation completed successfully: **9/9 tests passed** before publication.

## Remaining work

- move long-lived V2X credentials into TPM/secure-element storage;
- add persistent certificate/DID enrollment and revocation;
- make standardized ML-DSA the long-lived operational signature path when runtime support is available;
- perform full socket-level multi-node integration/HIL tests under packet loss, delay, replay, and MITM fault injection;
- harden the Go actuator/control API and its local process trust boundary.
