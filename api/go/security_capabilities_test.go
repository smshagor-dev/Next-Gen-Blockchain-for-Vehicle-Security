package main

import "testing"

func TestSecurityCapabilityOutputMarksClassicalComponents(t *testing.T) {
	t.Setenv("SMARTCAR_GO_ALLOW_CLASSICAL_ECDH_FALLBACK", "0")
	caps := securityCapabilityOutput()

	if got := caps["commitment_binding"]; got != "Pedersen - classical discrete-log assumption" {
		t.Fatalf("commitment_binding = %v", got)
	}
	if got := caps["range_proof_soundness"]; got != "Schnorr/classical assumption" {
		t.Fatalf("range_proof_soundness = %v", got)
	}
	if got := caps["fallback_ecdh_p256"]; got != "disabled_by_default/classical" {
		t.Fatalf("fallback_ecdh_p256 = %v", got)
	}
}

func TestIdentitySecurityOutputOpenRegistration(t *testing.T) {
	t.Setenv("SMARTCAR_IDENTITY_ADMISSION_POLICY", "OPEN_REGISTRATION")
	meta := identitySecurityOutput()

	if got := meta["identity_authenticity"]; got != true {
		t.Fatalf("identity_authenticity = %v", got)
	}
	if got := meta["sybil_resistance"]; got != false {
		t.Fatalf("sybil_resistance = %v", got)
	}
	if got := meta["identity_admission_policy"]; got != openRegistration {
		t.Fatalf("identity_admission_policy = %v", got)
	}
	if got := meta["warning"]; got != openRegistrationSybilWarning {
		t.Fatalf("warning = %v", got)
	}
}

func TestConsensusSecurityOutputSimpleMajority(t *testing.T) {
	meta := consensusSecurityOutput()
	if got := meta["majority_attack_resistant"]; got != false {
		t.Fatalf("majority_attack_resistant = %v", got)
	}
	if got := meta["protects_against_forward_majority_control"]; got != false {
		t.Fatalf("protects_against_forward_majority_control = %v", got)
	}
	if got := meta["consensus_model"]; got != consensusModelSimpleMajority {
		t.Fatalf("consensus_model = %v", got)
	}
}

func TestAdversarialValidationOutputDisablesGeneralDetectionClaim(t *testing.T) {
	meta := adversarialValidationOutput()
	if got := meta["supports_general_detection_claim"]; got != false {
		t.Fatalf("supports_general_detection_claim = %v", got)
	}
	if got := meta["detection_rate_headline_allowed"]; got != false {
		t.Fatalf("detection_rate_headline_allowed = %v", got)
	}
	if got := meta["attack_trials_per_type"]; got != 1 {
		t.Fatalf("attack_trials_per_type = %v", got)
	}
	if got := meta["adversarial_validation_level"]; got != "single_run_sanity_check" {
		t.Fatalf("adversarial_validation_level = %v", got)
	}
}

func TestContributionBoundaryOutputDisclaimsNewCryptoPrimitive(t *testing.T) {
	meta := contributionBoundaryOutput()
	if got := meta["claims_new_cryptographic_primitive"]; got != false {
		t.Fatalf("claims_new_cryptographic_primitive = %v", got)
	}
	if got := meta["contribution_type"]; got != "system_integration_and_validation_transparency" {
		t.Fatalf("contribution_type = %v", got)
	}
	novel, ok := meta["novel_components"].([]string)
	if !ok || len(novel) == 0 {
		t.Fatalf("novel_components missing or invalid: %v", meta["novel_components"])
	}
}

func TestComplexityBoundaryOutputDisclaimsFullSystemON(t *testing.T) {
	meta := complexityBoundaryOutput()
	if got := meta["overall_complexity_claim"]; got != "component_dependent" {
		t.Fatalf("overall_complexity_claim = %v", got)
	}
	if got := meta["full_system_o_n_claim"]; got != false {
		t.Fatalf("full_system_o_n_claim = %v", got)
	}
	if got := meta["naive_full_mesh_network_volume"]; got != "O(n^2)" {
		t.Fatalf("naive_full_mesh_network_volume = %v", got)
	}
	if got := meta["fl_aggregation"]; got != "O(n*d)" {
		t.Fatalf("fl_aggregation = %v", got)
	}
}

func TestPedersenPrivacyOutputCommitOnly(t *testing.T) {
	meta := pedersenPrivacyOutput()
	if got := meta["pedersen_mode"]; got != "COMMIT_ONLY" {
		t.Fatalf("pedersen_mode = %v", got)
	}
	if got := meta["commitment_homomorphic"]; got != true {
		t.Fatalf("commitment_homomorphic = %v", got)
	}
	if got := meta["aggregate_statistics_recoverable"]; got != false {
		t.Fatalf("aggregate_statistics_recoverable = %v", got)
	}
	if got := meta["requires_opening_for_aggregate"]; got != true {
		t.Fatalf("requires_opening_for_aggregate = %v", got)
	}
	if got := meta["secure_aggregation_implemented"]; got != false {
		t.Fatalf("secure_aggregation_implemented = %v", got)
	}
}

func TestReviewerAuditOutputInvalidClaimsFalse(t *testing.T) {
	audit := reviewerAuditOutput()
	if got := audit["paper_ready_claim_status"]; got != "corrected_but_requires_new_experiments" {
		t.Fatalf("paper_ready_claim_status = %v", got)
	}
	for _, key := range []string{
		"full_post_quantum_security_claim",
		"sybil_resistance_claim",
		"majority_attack_resistance_claim",
		"byzantine_robustness_claim",
		"general_100_percent_detection_claim",
		"new_crypto_primitive_claim",
		"whole_system_o_n_claim",
		"secure_aggregation_claim",
	} {
		if got := audit[key]; got != false {
			t.Fatalf("%s = %v", key, got)
		}
	}
	if got := audit["canonical_layer_count"]; got != "six implemented prototype layers" {
		t.Fatalf("canonical_layer_count = %v", got)
	}
	if got := audit["canonical_latency"]; got != "5.34 ms warm-start prototype pipeline latency" {
		t.Fatalf("canonical_latency = %v", got)
	}
}
