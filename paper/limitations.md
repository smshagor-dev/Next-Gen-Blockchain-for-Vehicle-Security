# Limitations

- Classical commitment/proof components remain: Pedersen binding and Schnorr-style proof soundness rely on classical discrete-log assumptions.
- The system provides no Sybil resistance under open registration.
- The simple-majority audit chain provides no majority-control resistance.
- The prototype provides no 51% protection under simple-majority consensus.
- `COMMIT_ONLY` Pedersen mode provides no secure aggregation and no readable aggregate statistics without openings.
- FL and adversarial results require real datasets, realistic attacks, repeated seeds, and statistical analysis before strong claims can be made.
- Scalability analysis is communication-volume analysis, not a distributed runtime benchmark yet.
- Latency microbenchmarks are local prototype measurements and do not replace production deployment benchmarks.
- The current state is corrected and bounded, but future validation is required before submission claims can be strengthened.

