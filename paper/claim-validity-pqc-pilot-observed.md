# Observed PQC handshake pilot — 2026-11-24

Run: https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45391371875
Head: a9b3cd8bca6f21acc9bb69ea6cd849a5d3bceeac
Artifact: https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45391371875/artifacts/14919560727
CI-reported ZIP SHA256: ace5e7ed09a55dc9ce6a9bdfbb7756c881824b3f018a5672e247d22063d5beea.

The native liboqs build, pinned binding install, three focused tests,
48-run campaign and artifact upload completed successfully. CI summary:

| Configuration | ML-KEM | ECDH | PSK | STRONG |
|---|---:|---:|---:|---:|
| native_mlkem | 8 | 0 | 0 | 8 |
| forced_classical_ecdh | 0 | 8 | 0 | 8 |
| forced_classical_psk | 0 | 0 | 8 | 8 |
| provider_missing_ecdh | 0 | 8 | 0 | 8 |
| provider_missing_psk | 0 | 0 | 8 | 8 |
| malformed_kem_psk | 0 | 0 | 8 | 8 |

All 48 pairs established matching session state; 40 were non-ML-KEM.
Operational STRONG remained 48/48 in the constructed wrapper. This is
actual local Python handshake execution with native crypto, not a C++
ledger execution, network capture or actual deployment attack. The
capability label is not itself a session guarantee. The archive contents
have not been independently downloaded/rehashed here. No inferential claim.

Collector follow-up: run 45391762330, head 903666f59f445dccded940475e2eb85f3339ba94,
both research jobs succeeded including observation controls and all three
campaigns. This verifies execution, not independent attestation.
