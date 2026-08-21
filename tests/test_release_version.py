import re
import unittest
from pathlib import Path

from release_metadata import INTERNAL_HARDENING_PHASE, RELEASE_VERSION, release_metadata
from security_capabilities import security_capability_output


class ReleaseVersionTests(unittest.TestCase):
    def test_canonical_version_is_3_0_2(self):
        value = Path("VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(value, "3.0.2")
        self.assertEqual(RELEASE_VERSION, value)
        self.assertRegex(value, r"^\d+\.\d+\.\d+$")

    def test_cmake_project_version_matches_canonical_version(self):
        text = Path("CMakeLists.txt").read_text(encoding="utf-8")
        match = re.search(
            r"project\(SmartCarBlockchain\s+VERSION\s+(\d+\.\d+\.\d+)\s+LANGUAGES\s+CXX\)",
            text,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), RELEASE_VERSION)
        self.assertIn('SMARTCAR_RELEASE_VERSION="${PROJECT_VERSION}"', text)

    def test_go_version_matches_canonical_version(self):
        text = Path("api/go/release_version.go").read_text(encoding="utf-8")
        match = re.search(r'const releaseVersion = "([^"]+)"', text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), RELEASE_VERSION)

    def test_security_capabilities_expose_release_without_stronger_claims(self):
        metadata = security_capability_output(False)
        self.assertEqual(metadata["release_version"], RELEASE_VERSION)
        self.assertEqual(metadata["release_channel"], "research_hardening")
        self.assertEqual(metadata["fallback_ecdh_p256"], "disabled_by_default/classical")

    def test_release_metadata_maps_public_version_to_internal_phase(self):
        metadata = release_metadata()
        self.assertEqual(metadata["release_version"], "3.0.2")
        self.assertEqual(INTERNAL_HARDENING_PHASE, "v3.2")
        self.assertEqual(metadata["internal_hardening_phase"], "v3.2")
        self.assertFalse(metadata["production_certified"])
        self.assertFalse(metadata["vehicle_safety_certified"])
        self.assertFalse(metadata["secret_values_exposed"])

    def test_release_docs_and_integrity_tooling_are_present(self):
        release_note = Path("docs/releases/v3.0.2.md")
        checklist = Path("docs/releases/v3.0.2-checklist.md")
        changelog = Path("CHANGELOG.md")
        integrity_tool = Path("release_integrity.py")
        integrity_test = Path("tests/test_release_integrity.py")
        for path in (release_note, checklist, changelog, integrity_tool, integrity_test):
            self.assertTrue(path.exists(), str(path))
        release_text = release_note.read_text(encoding="utf-8")
        self.assertIn("OmniGuard V2X v3.0.2", release_text)
        self.assertIn("Release Integrity Evidence", release_text)
        self.assertIn("v3.0.2", changelog.read_text(encoding="utf-8"))
        self.assertIn("Expected tag: `v3.0.2`", checklist.read_text(encoding="utf-8"))

    def test_publication_workflow_is_tag_and_commit_guarded(self):
        path = Path(".github/workflows/release-v3.0.2.yml")
        self.assertTrue(path.exists())
        text = path.read_text(encoding="utf-8")
        self.assertIn("- v3.0.2", text)
        self.assertIn('test "$GITHUB_REF_NAME" = "v3.0.2"', text)
        self.assertIn('git merge-base --is-ancestor "$GITHUB_SHA" origin/main', text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', text)
        self.assertIn('gh release view "$GITHUB_REF_NAME"', text)
        self.assertIn('--commit-sha "$GITHUB_SHA"', text)
        self.assertIn('--verify security-reports/release-integrity-manifest.json', text)
        self.assertIn('sha256sum -c SHA256SUMS', text)
        self.assertIn('gh release create "$GITHUB_REF_NAME"', text)
        self.assertIn('--verify-tag', text)
        self.assertIn('permissions:\n  contents: write', text)


if __name__ == "__main__":
    unittest.main()
