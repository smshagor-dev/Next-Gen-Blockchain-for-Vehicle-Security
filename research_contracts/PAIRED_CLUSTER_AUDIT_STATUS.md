# Paired incident cluster audit — research status (2026-11-19)

| Area | State | Evidence / next action |
| --- | --- | --- |
| Strict paired CSV ingest | Implemented; isolated validation | SHA-256 raw-file provenance, binary labels, duplicate incident rejection |
| Scenario leave-one-out effect | Implemented; isolated validation | Balanced-accuracy paired difference; class-loss explicitly undefined |
| Isolated negative controls | Completed | Five unittest cases passed in local standalone execution, 2026-11-19 |
| Exact GitHub branch suite | Blocked / pending | Run `python -m unittest discover -s tests -p 'test_paired_cluster_influence_audit.py' -v` |
| Relationship to merged #133 | Review required | Check for redundant implementation; retain only strict CSV provenance/negative-control improvements if overlap |
| Authentic VeReMi NextGen/CAN incident truth | Blocked | No independently authenticated labeled cohort available in this run |
| Matched baseline / attack efficacy | Upcoming | Same incident split, scenario-disjoint protocol, multi-seed independent runs |
| Hardware ingress and emergency stop | Partial / physical validation blocked | Preserve fail-closed actuation and local emergency override; no actuation in this module |
| Ledger independent finality | Blocked | Mock/SQLite correctness is not distributed consensus |
| Publication-ready claims | Blocked | No real effectiveness data; no significance inference from n >= 30 |

This audit is descriptive only and must not be cited as new V2X security effectiveness evidence. Existing fixture CSVs, 3-peer sanity tests, 5-iteration microbenchmarks and offline formulas are non-publishable as primary results.
