"""Non-actuating SIGKILL crash recovery controls; POSIX only."""
import os, tempfile, unittest
from pathlib import Path
from research_contracts.sigkill_recovery import PROTOCOLS, BOUNDARIES, run_case

@unittest.skipUnless(os.name=="posix","requires POSIX SIGKILL exit semantics")
class SigkillRecoveryTests(unittest.TestCase):
    def test_paired_boundaries(self):
        for protocol in PROTOCOLS:
            for boundary in BOUNDARIES:
                with self.subTest(protocol=protocol,boundary=boundary):
                    with tempfile.TemporaryDirectory() as tmp:
                        row=run_case(protocol,boundary,Path(tmp))
                    self.assertEqual(row["retry_rejected"],1)
                    self.assertEqual(row["checkpoint_preserved"],1)
                    self.assertEqual(row["inconsistent"],int(boundary=="first"))
                    self.assertEqual(row["local_claim"],int(boundary=="second" or protocol=="local_first"))
                    self.assertEqual(row["anchor_claim"],int(boundary=="second" or protocol=="reserve_first"))

    def test_repeatability(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=run_case("reserve_first","first",Path(tmp))
        with tempfile.TemporaryDirectory() as tmp:
            b=run_case("reserve_first","first",Path(tmp))
        self.assertEqual(a,b)

    def test_invalid_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                run_case("invalid","first",Path(tmp))
