# OmniGuard V2X — independent prior-art and originality audit (2026-11-14)

**Research decision:** No general claim that threshold witness endorsement,
multi-source consistency checking, trust-based misbehavior filtering, or
blockchain-backed V2X event sharing is newly invented in OmniGuard. Such
methods have substantial prior art. Novelty is **not yet established**.

## Closely related published work requiring comparisons

1. Si et al., "Verifiable event evidence sharing in VANETs via threshold
   multi-witness endorsement and controlled verification,"
   *Peer-to-Peer Networking and Applications*, 19, article 123 (2026),
   DOI: https://doi.org/10.1007/s12083-026-02285-9.
   This directly overlaps threshold witness validation and signed event
   evidence. Publication date 28 July 2026. Must compare event authenticity
   and witness assumptions, verification capability, cryptographic cost
   and collusion boundaries rather than claiming threshold endorsement is new.

2. "Comprehensive Review on Misbehavior Detection for Vehicular Ad Hoc
   Networks" (2022), DOI https://doi.org/10.1155/2022/4725805.
   The review explicitly identifies threshold-based event voting,
   cooperative multi-source consistency, and certificate/message
   plausibility as established lines, including earlier Hsiao et al.
   event validation work. Primary prior references must be retrieved
   and checked rather than citing only the review.

3. Qi et al., "A multi-dimensional trust model for misbehavior detection
   in vehicular ad hoc networks," *Journal of Information Security and
   Applications*, vol. 76, article 103528 (2023),
   DOI https://doi.org/10.1016/j.jisa.2023.103528.
   Discusses collusion-based adversarial manipulations and multi-attribute
   trust. Our quorum-by-identity primitive cannot claim collusion resistance.

4. Palomar et al., "Hindering false event dissemination in VANETs
   with proof-of-work mechanisms," *Transportation Research Part C*,
   vol. 23 (2012), pp. 85–97,
   DOI https://doi.org/10.1016/j.trc.2011.08.002.
   Distinguish bounded report corroboration from certificate-backed
   anti-spam/false-warning dissemination, and compare availability cost.

5. VeReMi NextGen dataset (2026):
   https://veremi-dataset.github.io/veremi-nextgen
   Publisher-defined CAM attacker labels are source-message labels, not
   independently annotated hazard-event truth. The source alone does
   not supply paired signed hub sessions or false-event ground truth.

## Restrained research hypothesis to evaluate

Under authenticated enrollment assumptions and a bounded report capacity,
a fixed *first-report spatial/temporal reference* gate can suffer
first-writer denial of honest corroboration. A mutually consistent
subset search can avoid this precise order dependency **provided an honest
quorum survives within the arrival window and per-incident memory pool**.

This is a falsifiable *engineering trade-off hypothesis*, not a novel
cryptographic protocol or demonstrated first-to-publish algorithm.
Existing consistency-based collaborative misbehavior methods may already
provide equivalent behavior.

## Confounding and strong negative cases to retain

- Enrolled colluders jointly fabricate a fully consistent false quorum.
- Sybil/identity enrollment assumptions can fail; station IDs are not
  independent physical sensor identities.
- Report pool exhaustion and high mobility deny honest subset placement.
- Network partition and zero-capture true hazards necessarily reduce
  remote alert availability under quorum.
- Relaxed spatial or temporal bounds can improve recall while increasing
  false admissions.
- 64 random-seed runs in this repository perturb one authored model;
  they are not 64 independently sourced studies or new world-state labels.
- A published 2026 multi-witness approach must be implemented as a
  comparable baseline before asserting improvement.

## Mandatory manuscript gates

- Retrieve and verify primary source metadata and the referenced original
  threshold event-validation literature.
- Freeze actual paired incident world truth, authenticated capture method,
  source enrollment and complete capture intervals.
- Compare published trust/multi-witness methods, authenticated-only relay,
  first-reference quorum and consistent-subset under identical independent
  traces and pre-registered baselines.
- Provide effect size, uncertainty, real runtime p95/p99, process/CPU/RAM,
  worst-case capacity, network drop and physical local-control isolation.
- Do not claim safety certification or independent empirical validation
  from CI scripts or checksum-only source files.

**Submission-ready originality claim:** NOT ESTABLISHED.
