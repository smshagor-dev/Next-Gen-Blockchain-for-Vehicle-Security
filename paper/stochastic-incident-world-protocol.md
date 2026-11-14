# Stochastic independent-world V2X study (software, pre-submission)

## What is implemented
\`experiments/v2x/stochastic_world_trials.py\` constructs an **internal seeded
world oracle** first, then separately synthesizes received authenticated-identity
report claims and runs the *existing* anchored and consistent-subset gates
on the **same** delivered messages. The received-packet log never supplies
the incident label to a policy. True incidents with zero packets remain FN.

This creates randomized, independently seeded **software-model** incident
trials. It DOES NOT provide independently captured *external* ground truth,
a realistic SUMO/NS-3 transport, live MAC verification, physical sensor
attestation, or empirical automotive safety. No statistical claim beyond
the defined synthetic stochastic model is justified.

## Frozen design (before experimental execution)
- RNG seeds: integers 0..63 (64 seeds), 16 opportunities per scenario/seed.
- World scenarios (7): true clean, true first-writer poison, true partition,
  true zero capture, false single compromised, false collusion, false zero capture.
- One seeded world-hazard opportunity per incident, external to message payload;
  fixed world labels come from scenario definitions.
- Honest packet dropout: 12% per report for true-clean and first-writer scenarios.
- Honest observed positions perturbed by ±0.00005 degrees; colluders use a
  matching false coordinate 0.02 degrees away from true world position.
- Packet arrival: 0..2 seconds; first-writer injected at -1 second.
- Policy settings: transport-authenticated-only relay, anchor quorum=2,
  consistent subset quorum=2, 100-m and 5-second pair compatibility,
  research default TTL/capacity.
- Primary exploratory paired comparison: difference in correctly located
  true first-writer hazard relay rates, subset minus anchor, with
  percentile bootstrap over **seeds**, not over highly correlated packets.
- Secondary descriptive results: incident-level TP/FP/TN/FN, corrupted-source
  relays, mislocated true-hazard relays, never-captured true incidents.
- Every policy invocation has synthetic (preverified) enrolled sender identity,
  **no actual cryptographic verification in this runner**.

## Run

\`\`\`sh
python -m unittest tests.test_stochastic_world_trials -v
python -m experiments.v2x.stochastic_world_trials \
  --output-dir /tmp/omni-world-trials \
  --seeds 64 --per-scenario 16
\`\`\`

Five audit artifacts are written: \`world.csv\`, \`deliveries.csv\`,
\`decisions.csv\`, \`summary.json\`, \`manifest.json\`. The manifest
pins complete result SHA-256 and hashes the algorithm source files.

## What results cannot show
A single simulator source's pseudorandom seeds do not establish an independent
source dataset, physical incident truth, range of V2X geographic/topographic
conditions, RF loss model realism, collusion resistance or general significance.
The authentic VeReMi CAM benchmark remains a separate message-level task and
must not be used as world-hazard truth.

## Gates still required for a *submit-ready original paper*
1. Independent world-state truth from external simulator/scenario labeling,
   not this internally constructed oracle; source hash and license.
2. Actual enrolled signed-session captures with replay/MAC verification.
3. Prespecified independent scenarios/seeds, stronger published baselines,
   correlated reporter and saturation cases.
4. External replication, comparison and statistics without post-hoc tuning.
5. Independent non-actuating physical bench measurements and safety reviewer
   sign-off: see \`paper/physical-hil-safety-evidence-protocol.md\`.

The protocol explicitly sets \`publication_ready=false\`.
