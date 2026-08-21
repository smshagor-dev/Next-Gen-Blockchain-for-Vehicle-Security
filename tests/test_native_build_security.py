import re
import unittest
from pathlib import Path


CMAKE = Path("CMakeLists.txt")
CPP = Path("blockchain.cpp")


class NativeBuildSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmake = CMAKE.read_text(encoding="utf-8")
        cls.cpp = CPP.read_text(encoding="utf-8")

    def test_native_cpu_optimization_is_opt_in(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_ENABLE_NATIVE_OPT\s+"[^"]+"\s+OFF\)',
        )
        self.assertIn("if(SMARTCAR_ENABLE_NATIVE_OPT)", self.cmake)
        self.assertIn("-march=native", self.cmake)

    def test_fast_math_is_explicit_lab_opt_in(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_ENABLE_UNSAFE_FAST_MATH\s+"[^"]+"\s+OFF\)',
        )
        self.assertIn("if(SMARTCAR_ENABLE_UNSAFE_FAST_MATH)", self.cmake)
        self.assertIn("-ffast-math", self.cmake)
        release_block = re.search(
            r"function\(smartcar_apply_release_options.*?endfunction\(\)",
            self.cmake,
            re.DOTALL,
        )
        self.assertIsNotNone(release_block)
        self.assertIn("$<$<CONFIG:Release>:-O2>", release_block.group(0))

    def test_fetched_json_archive_is_checksum_pinned(self):
        self.assertIn(
            "URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d",
            self.cmake,
        )

    def test_missing_liboqs_fails_closed_by_default(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_ALLOW_SIMULATED_PQC_BUILD\s+"[^"]+"\s+OFF\)',
        )
        self.assertIn(
            "if(NOT SMARTCAR_LIBOQS_TARGET AND NOT SMARTCAR_ALLOW_SIMULATED_PQC_BUILD)",
            self.cmake,
        )
        self.assertIn("message(FATAL_ERROR", self.cmake)
        self.assertIn("liboqs is required for the blockchain native target", self.cmake)

    def test_fail_closed_mode_can_be_forced_in_ci(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS\s+"[^"]+"\s+OFF\)',
        )
        self.assertIn("set(liboqs_FOUND FALSE)", self.cmake)

    def test_source_simulation_is_labeled_non_security_path(self):
        # The legacy source fallback remains for controlled demos, but standard
        # CMake builds are now blocked before producing such a binary unless the
        # explicit lab opt-in is supplied.
        self.assertIn("Dilithium2+Kyber512-SIMULATED", self.cpp)
        self.assertIn("not a PQ security claim", self.cpp)
        self.assertIn("LAB/DEMO ONLY", self.cmake)

    def test_ipo_is_not_default_release_behavior(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_ENABLE_IPO\s+"[^"]+"\s+OFF\)',
        )


if __name__ == "__main__":
    unittest.main()
