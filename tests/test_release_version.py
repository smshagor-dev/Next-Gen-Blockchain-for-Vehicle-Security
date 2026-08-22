import re
import subprocess
import unittest
from pathlib import Path

from release_metadata import INTERNAL_HARDENING_PHASE, RELEASE_VERSION, release_metadata
from security_capabilities import security_capability_output


class ReleaseVersionTests(unittest.TestCase):
    def test_canonical_version_is_3_0_3(self):
        value = Path("VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(value, "3.0.3")
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

    def test_release_metadata_is_conservative_v33(self):
        metadata = release_metadata()
        self.assertEqual(metadata["release_version"], "3.0.3")
        self.assertEqual(INTERNAL_HARDENING_PHASE, "v3.3")
        self.assertTrue(metadata["durable_pqc_identity"])
        self.assertTrue(metadata["signed_pqc_key_transitions"])
        self.assertTrue(metadata["mixed_generation_ledger_verification"])
        self.assertTrue(metadata["authenticated_local_rollback_anchor"])
        self.assertFalse(metadata["hardware_monotonic_rollback_protection"])
        self.assertFalse(metadata["hardware_pqc_provider_implemented"])
        self.assertFalse(metadata["production_certified"])
        self.assertFalse(metadata["vehicle_safety_certified"])
        self.assertFalse(metadata["secret_values_exposed"])

    def test_security_capabilities_expose_release_without_stronger_claims(self):
        metadata = security_capability_output(False)
        self.assertEqual(metadata["release_version"], RELEASE_VERSION)
        self.assertEqual(metadata["release_channel"], "research_hardening")
        self.assertEqual(metadata["fallback_ecdh_p256"], "disabled_by_default/classical")

    def test_v303_release_docs_and_supply_chain_tools_are_present(self):
        required = (
            "docs/releases/v3.0.3.md",
            "docs/releases/v3.0.3-checklist.md",
            "docs/security/SUPPLY_CHAIN.md",
            "docs/security/HISTORY_REMEDIATION.md",
            "release_integrity.py",
            "scripts/generate_sbom.py",
            "scripts/generate_provenance.py",
            "scripts/secret_scan.py",
            "scripts/create_v3_0_3_tag.sh",
            "scripts/ci_windows_go_backend_smoke.py",
            ".github/workflows/create-v3.0.3-tag.yml",
            ".github/workflows/release-v3.0.3.yml",
            ".github/workflows/windows-runtime-smoke.yml",
        )
        for item in required:
            self.assertTrue(Path(item).exists(), item)
        self.assertIn("Release Integrity Evidence", Path("docs/releases/v3.0.3.md").read_text(encoding="utf-8"))
        self.assertIn("Expected tag: `v3.0.3`", Path("docs/releases/v3.0.3-checklist.md").read_text(encoding="utf-8"))

    def test_security_baseline_validates_main_and_release_evidence(self):
        text = Path(".github/workflows/security-baseline.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"push:\s*\n\s*branches:\s*\n\s*- main\s*\n\s*- security/\*\*\s*\n\s*- release/\*\*")
        for required in (
            "Generate and verify release integrity manifest",
            "Run current-tree secret scan",
            "Generate SBOM and provenance",
            "Build pinned real-PQC v3.0.3 targets",
            "Run mixed-generation native runtime validation",
            "Run PQC rollback and recovery-state validation",
            "Run bounded Go fuzz campaigns",
            "Package v3.0.3 Linux validation artifacts",
        ):
            self.assertIn(required, text)

    def test_v303_manual_tag_workflow_is_exact_main_guarded(self):
        text = Path(".github/workflows/create-v3.0.3-tag.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text.split("permissions:", 1)[0])
        self.assertIn('test "${{ inputs.confirm }}" = "CREATE-v3.0.3"', text)
        self.assertIn('main_sha="$(git rev-parse origin/main)"', text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$main_sha"', text)
        for workflow in ("Security Baseline", "PKCS11 Source Conformance", "Windows Runtime Smoke"):
            self.assertIn(workflow, text)
        self.assertIn('--workflow "$workflow"', text)
        self.assertIn('--event push', text)
        self.assertIn("headSha,status,conclusion,url", text)
        self.assertIn('run.get("headSha") == target', text)
        self.assertIn('run.get("status") != "completed"', text)
        self.assertIn('run.get("conclusion") != "success"', text)
        self.assertIn('git tag -a "$TAG" "$main_sha"', text)
        self.assertIn("gh workflow run release-v3.0.3.yml", text)

    def test_v303_publication_workflow_is_tag_commit_guarded(self):
        text = Path(".github/workflows/release-v3.0.3.yml").read_text(encoding="utf-8")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("- v3.0.3", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertIn('test "$GITHUB_REF_NAME" = "v3.0.3"', text)
        self.assertIn('main_sha="$(git rev-parse origin/main)"', text)
        self.assertIn('test "$GITHUB_SHA" = "$main_sha"', text)
        self.assertIn('--commit-sha "$GITHUB_SHA"', text)
        self.assertIn("sha256sum -c SHA256SUMS", text)
        self.assertIn("gh release create", text)
        self.assertIn("--verify-tag", text)

    def test_local_tag_operator_is_guarded(self):
        path = Path("scripts/create_v3_0_3_tag.sh")
        text = path.read_text(encoding="utf-8")
        for required in (
            'MODE="${1:-}"',
            '"--check-only"',
            '"--push"',
            'if [[ "$branch" != "main" ]]',
            'remote_main_sha="$(git rev-parse origin/main)"',
            'if [[ "$local_sha" != "$remote_main_sha" ]]',
            'command -v gh',
            'gh auth status',
            '--workflow "$workflow"',
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
