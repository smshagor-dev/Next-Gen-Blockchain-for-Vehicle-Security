import tempfile
import unittest
from pathlib import Path
from research_contracts.can_trace_ingest import parse_trace


class CandumpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'trace.log'

    def parse(self, text):
        self.path.write_bytes(text.encode('ascii'))
        return parse_trace(self.path)

    def test_valid_and_label_free(self):
        result = self.parse('(1.000000001) can0 123#00FF\n(1.2) can0 00000123#AABB\n')
        self.assertEqual([r['dlc'] for r in result['records']], [2, 2])
        self.assertEqual(result['label_status'], 'unverified_unlabelled')
        self.assertEqual(result['records'][1]['timestamp_ns'], 1_200_000_000)

    def test_reject_can_fd(self):
        with self.assertRaises(ValueError): self.parse('(1.0) can0 123##1AABB\n')

    def test_reject_reverse_clock(self):
        with self.assertRaises(ValueError): self.parse('(2.0) can0 123#00\n(1.0) can0 123#00\n')

    def test_reject_odd_hex(self):
        with self.assertRaises(ValueError): self.parse('(1.0) can0 123#ABC\n')

    def test_reject_invalid_id(self):
        with self.assertRaises(ValueError): self.parse('(1.0) can0 FFFFFFFF#00\n')

    def test_reject_oversize(self):
        self.path.write_bytes(b'(1.0) can0 123#00\n')
        with self.assertRaises(ValueError): parse_trace(self.path, max_bytes=2)

    def test_reject_trailing_text(self):
        with self.assertRaises(ValueError): self.parse('(1.0) can0 123#00 ATTACK\n')

    def test_reject_symlink(self):
        target = Path(self.tmp.name) / 'target'
        target.write_text('(1.0) can0 123#00\n')
        self.path.symlink_to(target)
        with self.assertRaises(ValueError): parse_trace(self.path)


if __name__ == '__main__': unittest.main()
