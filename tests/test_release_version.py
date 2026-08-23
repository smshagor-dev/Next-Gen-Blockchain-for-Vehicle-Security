import re
import subprocess
import unittest
from pathlib import Path

from release_metadata import INTERNAL_HARDENING_PHASE, RELEASE_VERSION, release_metadata
from security_capabilities import security_capability_output


class ReleaseVersionTests(unittest.TestCase):
    def test_canonical_version_is_4_0_0(self):
        value = Path("VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(value, "4.0.0")
        self.assertEqual(RELEASE_VERSION, value)
        self.assertRegex(value, r"^\d+\.\d+\.\d+$")

    def test_cmake_and_go_versions_match(self):
        cmake = Path("CMakeLists.txt").read_text(encoding="utf-8")
        match = re.search(r"project\(SmartCarBlockchain\s+VERSION\s+(\d+\.\d+\.\d+)\s+LANGUAGES\s+CXX\)", cmake)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), RELEASE_VERSION)
        self.assertIn('SMARTCAR_RELEASE_VERSION="${PROJECT_VERSION}"', cmake)
        go = Path("api/go/release_version.go").read_text(encoding="utf-8")
        self.assertIn(f'const releaseVersion = "{RELEASE_VERSION}"', go)

    def test_release_metadata_is_conservative_v4(self):
        metadata = release_metadata()
        self.assertEqual(metadata["release_version"], "4.0.0")
        self.assertEqual(INTERNAL_HARDENING_PHASE, "v4.0")
        self.assertEqual(metadata["cumulative_security_line_from"], "2.0.1")
        self.assertTrue(metadata["real_pqc_native_validation"])
        self.assertTrue(metadata["durable_pqc_identity"])
        self.assertTrue(metadata["signed_pqc_key_transitions"])
        self.assertTrue(metadata["mixed_generation_ledger_verification"])
        self.assertTrue(metadata["authenticated_local_rollback_anchor"])
        self.assertFalse(metadata["hardware_monotonic_rollback_protection"])
        self.assertTrue(metadata["hardware_pqc_provider_implemented"])
        self.assertTrue(metadata["pkcs11_v32_provider_adapter_implemented"])
        self.assertFalse(metadata["pkcs11_production_token_validated"])
        self.assertTrue(metadata["authenticated_live_runtime_stream"])
        self.assertTrue(metadata["live_runtime_hmac_authenticated"])
        self.assertTrue(metadata["source_backed_runtime_security_strength"])
        self.assertFalse(metadata["production_certified"])
        self.assertFalse(metadata["vehicle_safety_certified"])
        self.assertFalse(metadata["secret_values_exposed"])

    def test_security_capabilities_expose_strength_without_fake_score(self):
        metadata = security_capability_output(False)
        self.assertEqual(metadata["release_version"], RELEASE_VERSION)
        self.assertEqual(metadata["release_channel"], "research_hardening")
        self.assertEqual(metadata["fallback_ecdh_p256"], "disabled_by_default/classical")
        self.assertIn("STRONG/GUARDED/DEGRADED/RISK", metadata["runtime_security_strength"])
        self.assertFalse(metadata["runtime_security_strength_numeric_score"])
        self.assertFalse(metadata["runtime_security_strength_certification_claim"])

    def test_v400_release_docs_and_supply_chain_tools_are_present(self):
        required = (
            "docs/releases/v4.0.0.md",
            "docs/releases/v4.0.0-checklist.md",
            "docs/security/SUPPLY_CHAIN.md",
            "docs/security/HISTORY_REMEDIATION.md",
            "release_integrity.py",
            "runtime_security_strength.py",
            "scripts/generate_sbom.py",
            "scripts/generate_provenance.py",
            "scripts/secret_scan.py",
            "scripts/create_v4_0_0_tag.sh",
            "scripts/ci_windows_go_backend_smoke.py",
            ".github/workflows/create-v4.0.0-tag.yml",
            ".github/workflows/release-v4.0.0.yml",
            ".github/workflows/windows-runtime-smoke.yml",
        )
        for item in required:
            self.assertTrue(Path(item).exists(), item)
        notes = Path("docs/releases/v4.0.0.md").read_text(encoding="utf-8")
        self.assertIn("v2.0.1 — Security Baseline", notes)
        self.assertIn("v3.0.3 — Durable PQC Identity", notes)
        self.assertIn("Source-Backed Runtime Security Strength", notes)
        self.assertIn("Release Integrity Evidence", notes)
        self.assertIn("Expected tag: `v4.0.0`", Path("docs/releases/v4.0.0-checklist.md").read_text(encoding="utf-8"))

    def test_security_baseline_validates_v4_release_evidence(self):
        text = Path(".github/workflows/security-baseline.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"push:\s*\n\s*branches:\s*\n\s*- main\s*\n\s*- security/\*\*\s*\n\s*- release/\*\*")
        for required in (
            "tests.test_runtime_security_strength",
            "tests.test_v400_dashboard_security_strength",
            "Build pinned real-PQC v4.0.0 targets",
            "sbom-v4.0.0.cdx.json",
            "provenance-v4.0.0.json",
            "Package v4.0.0 Linux validation artifacts",
        ):
            self.assertIn(required, text)

    def test_v400_manual_tag_workflow_is_exact_main_guarded(self):
        text = Path(".github/workflows/create-v4.0.0-tag.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text.split("permissions:", 1)[0])
        self.assertIn('test "${{ inputs.confirm }}" = "CREATE-v4.0.0"', text)
        self.assertIn('main_sha="$(git rev-parse origin/main)"', text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$main_sha"', text)
        for workflow in ("Security Baseline", "PKCS11 Source Conformance", "Windows Runtime Smoke"):
            self.assertIn(workflow, text)
        self.assertIn('--event push', text)
        self.assertIn('git tag -a v4.0.0 "$main_sha"', text)
        self.assertIn("gh workflow run release-v4.0.0.yml", text)

    def test_v400_publication_workflow_is_tag_commit_guarded(self):
        text = Path(".github/workflows/release-v4.0.0.yml").read_text(encoding="utf-8")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("- v4.0.0", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertIn('test "$GITHUB_REF_NAME" = "v4.0.0"', text)
        self.assertIn('main_sha="$(git rev-parse origin/main)"', text)
        self.assertIn('test "$GITHUB_SHA" = "$main_sha"', text)
        self.assertIn('--commit-sha "$GITHUB_SHA"', text)
        self.assertIn("sha256sum -c SHA256SUMS", text)
        self.assertIn("gh release create", text)
        self.assertIn("--verify-tag", text)

    def test_local_tag_operator_is_guarded(self):
        path = Path("scripts/create_v4_0_0_tag.sh")
        text = path.read_text(encoding="utf-8")
        for required in (
            'TAG="v4.0.0"',
            'MODE="${1:-}"',
            '"--check-only"',
            '"--push"',
            'if [[ "$branch" != "main" ]]',
            'remote_main_sha="$(git rev-parse origin/main)"',
            'if [[ "$local_sha" != "$remote_main_sha" ]]',
            'command -v gh',
            'gh auth status',
            '--event push',
            'git tag -a "$TAG" "$local_sha"',
            'git push origin "refs/tags/$TAG"',
        ):
            self.assertIn(required, text)
        for workflow in ("Security Baseline", "PKCS11 Source Conformance", "Windows Runtime Smoke"):
            self.assertIn(workflow, text)
        subprocess.run(["bash", "-n", str(path)], check=True)


if __name__ == "__main__":
    unittest.main()
