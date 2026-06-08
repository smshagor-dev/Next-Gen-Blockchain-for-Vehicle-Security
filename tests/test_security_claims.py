import os
import unittest
from pathlib import Path
from unittest.mock import patch

from federated_learning import PROTOTYPE_FL_WARNING, fl_validation_metadata
from security_capabilities import (
    ECDH_P256_WARNING,
    adversarial_validation_metadata,
    complexity_boundary_metadata,
    contribution_boundary_metadata,
    reviewer_audit_metadata,
    security_capability_output,
)
from zkp_privacy import pedersen_privacy_metadata


class SecurityClaimTests(unittest.TestCase):
    def test_ecdh_fallback_disabled_by_default(self):
        with patch.dict(os.environ, {"SMARTCAR_V2X_ALLOW_CLASSICAL_ECDH_FALLBACK": "0"}, clear=False):
            from v2x_protocol import DynamicCryptoAgilityLayer

            layer = DynamicCryptoAgilityLayer("test_default")
            self.assertFalse(layer._allow_ecdh_fallback)
            self.assertNotIn("ecdh_pubkey", layer.handshake_hello_payload())

    def test_enabling_ecdh_fallback_warns(self):
        with patch.dict(os.environ, {"SMARTCAR_V2X_ALLOW_CLASSICAL_ECDH_FALLBACK": "1"}, clear=False):
            from v2x_protocol import DynamicCryptoAgilityLayer

            with self.assertLogs("SmartCarV2X", level="WARNING") as logs:
                layer = DynamicCryptoAgilityLayer("test_enabled")
            self.assertTrue(layer._allow_ecdh_fallback)
            self.assertTrue(any(ECDH_P256_WARNING in msg for msg in logs.output))

    def test_security_capability_marks_pedersen_binding_classical(self):
        caps = security_capability_output(False)
        self.assertEqual(caps["commitment_binding"], "Pedersen - classical discrete-log assumption")
        self.assertEqual(caps["fallback_ecdh_p256"], "disabled_by_default/classical")

    def test_gui_and_security_metadata_do_not_claim_fully_post_quantum(self):
        forbidden = "fully post-quantum"
        targets = [
            Path("dashboard.py"),
            Path("smartcar_backend.py"),
            Path("security_capabilities.py"),
            Path("api/go/main.go"),
        ]
        for target in targets:
            self.assertNotIn(forbidden, target.read_text(encoding="utf-8").lower(), str(target))

    def test_security_assumptions_doc_exists(self):
        doc = Path("docs/security-assumptions.md")
        self.assertTrue(doc.exists())
        text = doc.read_text(encoding="utf-8")
        self.assertIn("Pedersen Commitment", text)
        self.assertIn("ECDH-P256", text)

    def test_fl_metadata_downgrades_byzantine_robustness_claim(self):
        meta = fl_validation_metadata()
        self.assertEqual(meta["fl_validation_level"], "prototype_sanity_check")
        self.assertEqual(meta["num_peers"], 3)
        self.assertEqual(meta["samples_per_peer"], 10)
        self.assertEqual(meta["test_samples"], 24)
        self.assertEqual(meta["byzantine_peers"], 1)
        self.assertEqual(meta["attack_type"], "100x_weight_delta")
        self.assertFalse(meta["statistical_significance"])
        self.assertFalse(meta["supports_byzantine_robustness_claim"])

    def test_fl_warning_appears_for_tiny_sanity_check(self):
        meta = fl_validation_metadata(num_peers=3, test_samples=24)
        self.assertIn(PROTOTYPE_FL_WARNING, meta["warnings"])

    def test_readme_and_docs_do_not_make_unqualified_byzantine_robust_claims(self):
        allowed_qualifiers = [
            "not ",
            "not statistically sufficient",
            "does not",
            "too small",
            "warning:",
            "unsupported",
            "not supported",
        ]
        targets = [Path("readme.md"), *Path("docs").glob("*.md")]
        for target in targets:
            text = target.read_text(encoding="utf-8").lower()
            for line in text.splitlines():
                if "byzantine-robust" in line or "byzantine robustness" in line:
                    self.assertTrue(
                        any(q in line for q in allowed_qualifiers),
                        f"Unqualified Byzantine robustness claim in {target}: {line}",
                    )

    def test_fl_validation_plan_scaffold_is_configurable(self):
        plan = Path("experiments/fl_validation_plan.py")
        self.assertTrue(plan.exists())
        from experiments.fl_validation_plan import DEFAULT_ATTACK_TYPES, DEFAULT_PEER_COUNTS, build_validation_grid

        self.assertEqual(DEFAULT_PEER_COUNTS, [3, 5, 10, 20, 50])
        self.assertIn("sign-flip", DEFAULT_ATTACK_TYPES)
        self.assertIn("label-flip", DEFAULT_ATTACK_TYPES)
        self.assertIn("gaussian-noise", DEFAULT_ATTACK_TYPES)
        self.assertIn("scaling-attack", DEFAULT_ATTACK_TYPES)
        self.assertIn("backdoor-trigger", DEFAULT_ATTACK_TYPES)
        self.assertIn("random-update", DEFAULT_ATTACK_TYPES)
        grid = build_validation_grid([5, 10], [0.0, 0.2], ["sign-flip", "random-update"], [0, 1])
        self.assertEqual(len(grid), 16)
        self.assertEqual(grid[0].peers, 5)
        self.assertEqual(grid[-1].attack_type, "random-update")

    def test_adversarial_metadata_disables_general_detection_claims(self):
        meta = adversarial_validation_metadata()
        self.assertEqual(meta["adversarial_validation_level"], "single_run_sanity_check")
        self.assertFalse(meta["supports_general_detection_claim"])
        self.assertFalse(meta["detection_rate_headline_allowed"])
        self.assertEqual(meta["attack_trials_per_type"], 1)
        self.assertFalse(meta["statistical_significance"])
        self.assertIn("350_kmh_speed", meta["known_trivial_triggers"])
        self.assertIn("100x_fl_weight_delta", meta["known_trivial_triggers"])

    def test_metrics_source_of_truth_exists_and_pins_latency(self):
        doc = Path("docs/metrics-source-of-truth.md")
        self.assertTrue(doc.exists())
        text = doc.read_text(encoding="utf-8")
        self.assertIn("5.34 ms warm-start prototype pipeline latency", text)
        for line in text.splitlines():
            if "3.57 ms" in line:
                self.assertTrue("Deprecated" in line or "deprecated" in line)

    def test_no_detection_layer_or_latency_overclaims_remain(self):
        forbidden = [
            "100%" + " detection",
            "100%" + " adversarial detection",
            "100%" + " detection across six attacks",
            "hardware-level actuation across " + "thirteen composable security layers",
            "thirteen " + "layers",
            "13 " + "layers",
        ]
        targets = [
            Path("readme.md"),
            Path("dashboard.py"),
            Path("smartcar_backend.py"),
            Path("security_capabilities.py"),
            Path("api/go/main.go"),
            *Path("docs").glob("*.md"),
        ]
        for target in targets:
            text = target.read_text(encoding="utf-8").lower()
            for phrase in forbidden:
                if phrase == "100%" + " detection":
                    for line in text.splitlines():
                        if phrase in line:
                            self.assertIn("claim", line, str(target))
                            self.assertIn("no", line, str(target))
                    continue
                self.assertNotIn(phrase.lower(), text, str(target))
            for line in text.splitlines():
                if "3.57 ms" in line:
                    self.assertIn("deprecated", line.lower(), str(target))

    def test_dashboard_does_not_show_100_percent_detection(self):
        text = Path("dashboard.py").read_text(encoding="utf-8").lower()
        for line in text.splitlines():
            if "100%" + " detection" in line:
                self.assertIn("claim", line)
                self.assertIn("no", line)
        self.assertIn("detection rate headline: {headline}", text)
        self.assertIn("single-run sanity check", text)

    def test_contribution_boundary_doc_exists(self):
        doc = Path("docs/contribution-boundary.md")
        self.assertTrue(doc.exists())
        text = doc.read_text(encoding="utf-8")
        self.assertIn("does not introduce new cryptographic primitives", text)
        self.assertIn("Cross-layer prototype integration", text)
        self.assertIn("Reused Standard Components", text)
        self.assertIn("Not Claimed", text)

    def test_contribution_metadata_disclaims_new_crypto_primitive(self):
        meta = contribution_boundary_metadata()
        self.assertFalse(meta["claims_new_cryptographic_primitive"])
        self.assertEqual(meta["contribution_type"], "system_integration_and_validation_transparency")
        self.assertIn("ML-KEM/Kyber", meta["reused_components"])
        self.assertIn("Pedersen commitments", meta["reused_components"])
        self.assertIn("cross-layer prototype integration", meta["novel_components"])
        self.assertIn("validation-plan scaffolding", meta["novel_components"])

    def test_readme_and_docs_do_not_claim_unsupported_novelty(self):
        forbidden = [
            "first post-quantum blockchain " + "v2x framework",
            "fully novel " + "ses protocol",
            "new sybil-resistant " + "did",
            "new 51% attack resistant " + "blockchain",
            "first full pq blockchain " + "v2x framework",
        ]
        negative_context = [
            "does not",
            "rather than",
            "not claimed",
            "new pq cryptographic primitive",
            "no cryptographic",
            "no new cryptographic",
        ]
        targets = [Path("readme.md"), *Path("docs").glob("*.md")]
        for target in targets:
            text = target.read_text(encoding="utf-8").lower()
            for phrase in forbidden:
                self.assertNotIn(phrase, text, str(target))
            for line in text.splitlines():
                if "new cryptographic " + "primitive" in line or "novel cryptographic " + "primitive" in line:
                    self.assertTrue(
                        any(marker in line for marker in negative_context),
                        f"Unsupported novelty claim in {target}: {line}",
                    )

    def test_dashboard_has_contribution_boundary_wording(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertIn("Contribution Boundary", text)
        self.assertIn("New cryptographic primitive:", text)
        self.assertIn("system integration + validation transparency", text)

    def test_complexity_analysis_doc_exists(self):
        doc = Path("docs/complexity-analysis.md")
        self.assertTrue(doc.exists())
        text = doc.read_text(encoding="utf-8")
        self.assertIn("component-dependent complexity", text)
        self.assertIn("O(n^2)", text)
        self.assertIn("FL aggregation", text)
        self.assertIn("O(n*d)", text)

    def test_complexity_metadata_disclaims_full_system_o_n(self):
        meta = complexity_boundary_metadata()
        self.assertEqual(meta["overall_complexity_claim"], "component_dependent")
        self.assertFalse(meta["full_system_o_n_claim"])
        self.assertEqual(meta["naive_full_mesh_network_volume"], "O(n^2)")
        self.assertEqual(meta["single_proposal_vote_collection"], "O(n)")
        self.assertEqual(meta["fl_aggregation"], "O(n*d)")
        self.assertEqual(meta["chain_audit"], "O(k)")

    def test_readme_and_docs_do_not_claim_whole_system_o_n(self):
        forbidden = [
            "the system is " + "o(n)",
            "whole system is " + "o(n)",
            "full system is " + "o(n)",
            "overall complexity is " + "o(n)",
            "end-to-end complexity is " + "o(n)",
        ]
        targets = [Path("readme.md"), *Path("docs").glob("*.md")]
        for target in targets:
            text = target.read_text(encoding="utf-8").lower()
            for phrase in forbidden:
                self.assertNotIn(phrase, text, str(target))

    def test_dashboard_has_complexity_boundary_wording(self):
        text = Path("dashboard.py").read_text(encoding="utf-8").lower()
        self.assertIn("component-dependent", text)
        self.assertIn("complexity boundary", text)
        self.assertIn("full system o(n):", text)

    def test_pedersen_privacy_metadata_commit_only(self):
        meta = pedersen_privacy_metadata()
        self.assertEqual(meta["pedersen_mode"], "COMMIT_ONLY")
        self.assertTrue(meta["commitment_homomorphic"])
        self.assertFalse(meta["aggregate_statistics_recoverable"])
        self.assertTrue(meta["requires_opening_for_aggregate"])
        self.assertFalse(meta["secure_aggregation_implemented"])

    def test_pedersen_aggregation_doc_exists(self):
        doc = Path("docs/pedersen-aggregation-model.md")
        self.assertTrue(doc.exists())
        text = doc.read_text(encoding="utf-8")
        self.assertIn("COMMIT_ONLY", text)
        self.assertIn("aggregate remains hidden", text)
        self.assertIn("SECURE_AGGREGATION_FUTURE", text)
        self.assertIn("Not implemented", text)

    def test_no_mean_velocity_extraction_without_openings_claim(self):
        allowed_context = [
            "not recoverable",
            "not readable",
            "unless participants provide valid openings",
            "without an opening",
            "commitments alone",
        ]
        targets = [Path("readme.md"), *Path("docs").glob("*.md")]
        for target in targets:
            text = target.read_text(encoding="utf-8").lower()
            for line in text.splitlines():
                if "mean velocity" in line or "average velocity" in line:
                    self.assertTrue(
                        any(marker in line for marker in allowed_context),
                        f"Unsupported aggregate-statistics claim in {target}: {line}",
                    )

    def test_dashboard_pedersen_commit_only_does_not_show_aggregate_available(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertIn("Pedersen Mode: Commit-only", text)
        self.assertIn("Aggregate Statistics Recoverable: {aggregate_available}", text)
        self.assertIn('aggregate_available = "Yes" if privacy.get("aggregate_statistics_recoverable", False) else "No"', text)
        self.assertIn("Secure Aggregation: {secure_aggregation}", text)

    def test_reviewer_issue_resolution_matrix_exists(self):
        doc = Path("docs/reviewer-issue-resolution-matrix.md")
        self.assertTrue(doc.exists())
        text = doc.read_text(encoding="utf-8")
        for issue in [
            "Overstated post-quantum security",
            "Invalid Sybil-resistance theorem",
            "Incorrect 51% attack theorem",
            "Weak FL evaluation",
            "100% detection / trivial attack tests",
            "Inconsistent layer counts",
            "Inconsistent latency numbers",
            "Unclear novelty",
            "O(n) vs O(n²) complexity mismatch",
            "Pedersen aggregate-statistics claim",
        ]:
            self.assertIn(issue, text)

    def test_reviewer_audit_metadata_all_invalid_claims_false(self):
        audit = reviewer_audit_metadata()
        self.assertEqual(audit["paper_ready_claim_status"], "corrected_but_requires_new_experiments")
        false_claim_keys = [
            "full_post_quantum_security_claim",
            "sybil_resistance_claim",
            "majority_attack_resistance_claim",
            "byzantine_robustness_claim",
            "general_100_percent_detection_claim",
            "new_crypto_primitive_claim",
            "whole_system_o_n_claim",
            "secure_aggregation_claim",
        ]
        for key in false_claim_keys:
            self.assertFalse(audit[key], key)
        self.assertEqual(audit["canonical_layer_count"], "six implemented prototype layers")
        self.assertEqual(audit["canonical_latency"], "5.34 ms warm-start prototype pipeline latency")

    def test_readme_has_reviewer_driven_corrections_section(self):
        text = Path("readme.md").read_text(encoding="utf-8")
        self.assertIn("Reviewer-Driven Corrections", text)
        self.assertIn("corrected_but_requires_new_experiments", text)

    def test_dashboard_has_reviewer_audit_card_wording(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertIn("Reviewer Audit", text)
        self.assertIn("Paper claim status: corrected but requires new experiments", text)
        self.assertIn("Full PQ claim:", text)
        self.assertIn("Secure aggregation claim:", text)

    def test_paper_rewrite_scaffold_files_exist(self):
        expected = [
            "revised-title.md",
            "revised-abstract.md",
            "contributions.md",
            "threat-model.md",
            "security-assumptions.md",
            "evaluation-plan.md",
            "limitations.md",
            "reviewer-response-summary.md",
        ]
        for name in expected:
            self.assertTrue(Path("paper", name).exists(), name)

    def test_revised_abstract_avoids_banned_headline_claims(self):
        text = Path("paper/revised-abstract.md").read_text(encoding="utf-8").lower()
        banned = [
            "fully post-quantum",
            "51% resistant",
            "sybil resistant",
            "100% detection",
            "100 percent detection",
            "accepted-ready",
        ]
        for phrase in banned:
            self.assertNotIn(phrase, text)
        self.assertIn("hybrid-security prototype", text)
        self.assertIn("ml-kem/kyber", text)
        self.assertIn("larger experiments", text)

    def test_paper_limitations_names_sybil_and_majority_control_limits(self):
        text = Path("paper/limitations.md").read_text(encoding="utf-8").lower()
        self.assertIn("no sybil resistance", text)
        self.assertIn("no majority-control resistance", text)

    def test_paper_contributions_disclaims_new_crypto_primitive(self):
        text = Path("paper/contributions.md").read_text(encoding="utf-8").lower()
        self.assertIn("does not introduce a new cryptographic primitive", text)
        self.assertIn("system integration plus validation transparency", text)


if __name__ == "__main__":
    unittest.main()
