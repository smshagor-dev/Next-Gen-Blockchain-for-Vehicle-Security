# V2X research status: TCP rejection isolation (2026-11-23)

- **Completed in branch:** Catch OSError on saturated rejected peer close, keeping accept loop alive; deterministic non-actuating regression for saturation, close failure, and capacity recovery.
- **Partial:** TCP MAC/replay/freshness integration and worker-lifetime limits require exact-checkout end-to-end tests.
- **Blocked:** No independent hardware, VeReMi/CAN source-pinned campaigns, or measured effectiveness evidence; full checkout validation pending.
- **Upcoming:** Execute focused and full suites; inspect exception classes from actual sockets; run real loopback saturation campaign with authenticated envelopes, capture latency and drop counts against frozen baselines.
- **Claim ledger:** This is an ingress reliability control, NOT original-paper effectiveness evidence; no hardware safety or statistical significance claimed.
