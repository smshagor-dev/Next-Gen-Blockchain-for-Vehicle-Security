# OmniGuard V2X scientific evidence status matrix — 2026-11-12

This file tracks actual engineering, code review state and reproducible
evidence. **Working software is not itself an original scientific claim.**
This status update belongs to draft PR #87 (stacked on draft PR #85);
it is not yet merged into main.

| Workstream | Engineering state | Verified evidence | Scientific blockers and next task |
| --- | --- | --- | --- |
| Authenticated Pi TCP ingress and safety interlock | MERGED PR #74, software implemented | PR #74 tests/CI; bounded authenticated ingress and bench-gated actuation branch merged to main | Physical bench/HIL emergency-local-control evidence, formal hazard review and real device tests absent |
| Ledger crash consistency / smart-contract finality | PARTIAL | Existing software hardening and test suites | Crash/fault injection on real persistence boundary, replicated ledger fault evidence, mock-vs-chain finality gap |
| V2X evidence-gated network event admission | MERGED PR #80, opt-in implementation | Security and hub protocol regression tests, quorum/state invariants, replay and valid-MAC command-smuggling checks | Original novelty compared with trusted literature not established; independent incident-world ground truth, malicious *enrolled* collusion, partitions, false-negative/availability and physical-control isolation experiments missing |
| Statistical inference and FL claim integrity | MERGED PRs #77/#78, code | n>=30 false significance removed; exploratory paired bootstrap/sign-flip/Holm tool validated by contract tests | No independently repeated authentic candidate-vs-baseline experiments; no power/preregistration/confirmatory uncertainty |
| Original VeReMi NextGen importer | MERGED PR #82, exercised on actual release | SHA-verified highway_2 baseline+dataReplay source archives, nested Train/Validation/Test ZIP parsing, 99,937 CAM receptions per archive, CAM label preservation, CI | Confirm dataset reuse license; source CAM labels are message-level, not physical event-world truth |
| Receiver duplicates and source partition hygiene | IMPLEMENTED, authentic source audit | Highway_2 45,101 unique heuristic CAM fingerprints from 99,937 receptions, 54,836 duplicated receiver matches; source-partition checks | Fingerprint collisions and latent simulator/vehicle correlations not ruled out; no independent physical identity attestation |
| Independently annotated incident split hygiene | MERGED PR #83, structural audit only | Fail-closed sample/group leakage validator and synthetic contract tests | No authenticated original incident annotations, world-truth proof, temporal exposure controls or independent label audit |
| Fixed-source CAM held-out baselines | DRAFT PR #85, actual source evaluation | Highway_2 dataReplay Test 18,892 deduplicated fingerprints; source Validation-only thresholds; full confusion matrices; source CI | Single original scenario, post-hoc motion method, no SOTA comparator; CAM classification is not event admission or safety |
| Distinct-scenario CAM transfer | DRAFT PR #87, actual source evaluation | Official Urban_2 dataReplay 812,795 CAM receptions, 246,082 distinct heuristic fingerprints, 113,779 Test; frozen Highway_2 Validation thresholds; 9/9 transfer tests and real archive jobs passed; artifact 13969084219 | Same simulator family, post-hoc feature, no independent simulation seeds or preregistered design; recall remains low, no original incident security conclusions |
| CAN/in-vehicle dataset mapping | BLOCKED | No genuine incident-level vehicle/ECU experiment materialized in this run | Establish license, causal labels and safety-isolated boundary with external benchmark protocol |
| Genuine V2X evidence-gated admission evaluation | BLOCKED (CORE SCIENTIFIC QUESTION) | Candidate policy code exists; synthetic scenarios are *software tests only* | Generate/obtain independent physical-world event labels, enrolled adversary scenarios, correlated reports, quorum availability, network fault/partition, same-split published baseline comparisons |
| Runtime CPU/RAM/network latency scaling | BLOCKED | Isolated software microbenchmarks exist but are not representative | Real measured multi-node campaign, runtime provenance, resource traces, independent seeds and uncertainty |
| Scientific originality, literature and manuscript | BLOCKED | Falsifiable hypotheses and descriptive CAM datasets ready; no validated new primitive claimed | Prior-art comparison, original mechanism advantage/limitations, full system ablations, negative results, independent statistical inference and final numeric-claim provenance |

## Latest verified actual CAM transfer (auxiliary only)

Pinned publisher: VeReMi NextGen v1.0.0; source Highway_2 dataReplay SHA256
08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea;
target Urban_2 dataReplay SHA256
9984cd0cfa32d31f607788a2a1c53c72970c6786563c785cce9b989bb7ce7777.

Official [CI run 43274403228](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43274403228)
was successful, 9/9 synthetic transfer contract tests plus both genuine publisher
archive ingest/analysis jobs passed. Urban Test distinct source fingerprints:
113,779, including 20,189 attacker-labelled and 93,590 non-attacker-labelled.

The exploratory post-hoc temporal motion heuristic on fixed source
thresholds has TP=3,076, FP=340, TN=93,250, FN=17,113 (CAM-level),
precision 90.05%, recall 15.24%, F1 26.06%, FPR 0.36%. These are
descriptive source-message figures only. They do not establish independent
sample inference, safety certification or physically observed false hazard
admission.

See paper/highway-to-urban-observed-results.md for all baselines, measured
thresholds, hashes, negative observations and interpretation restrictions.

## Upcoming implementation priorities

1. Keep PRs #85 and #87 draft until CI, source licensing, stacked dependencies
   and methodological review are completed. Do not merge unverified claims.
2. Define a reproducible independent world-truth incident-labelling protocol
   tied to the simulator's physical events and receiver trust context;
   validate every label and physical origin. Do not infer incident truth from
   a CAM attacker flag or an unauthenticated payload ID.
3. Implement fixed-trace, same-attack/same-seed candidate vs published trust
   admission baselines including colluding enrolled identities and network
   loss/partition conditions; quantify availability and time-to-alert.
4. Measure runtime CPU/RAM/latency at controlled participant counts and
   independently repeated trials, then run the paired statistical tool with
   uncertainty/effect sizes and honest negative results.
5. Only then assess distinct scientific contribution, choose journal format,
   validate every reference and update manuscript numeric-claim ledger.

**Submission-ready original research: NOT ESTABLISHED.**
