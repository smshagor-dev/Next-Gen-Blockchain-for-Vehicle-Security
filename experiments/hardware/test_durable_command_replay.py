"""Local synthetic crash/restart and replay tests; not HIL evidence."""
import tempfile
import unittest
from pathlib import Path
from durable_command_replay import DurableCommandReplayGate

class DurableReplayTests(unittest.TestCase):
    def test_restart_rejects_replay(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / 'commands.sqlite')
            gate = DurableCommandReplayGate(path)
            self.assertTrue(gate.claim_verified(device_id='bench1', nonce='aa' * 16))
            gate.close()
            gate = DurableCommandReplayGate(path)
            self.assertFalse(gate.claim_verified(device_id='bench1', nonce='aa' * 16))
            gate.close()

    def test_identity_scope(self):
        with tempfile.TemporaryDirectory() as d:
            gate = DurableCommandReplayGate(str(Path(d) / 'commands.sqlite'))
            self.assertTrue(gate.claim_verified(device_id='a', nonce='aa' * 16))
            self.assertTrue(gate.claim_verified(device_id='b', nonce='aa' * 16))
            gate.close()

    def test_parallel_connections_claim_only_once(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / 'commands.sqlite')
            first = DurableCommandReplayGate(path)
            second = DurableCommandReplayGate(path)
            self.assertTrue(first.claim_verified(device_id='a', nonce='bb' * 16))
            self.assertFalse(second.claim_verified(device_id='a', nonce='bb' * 16))
            first.close(); second.close()

    def test_memory_database_rejected(self):
        with self.assertRaises(ValueError):
            DurableCommandReplayGate(':memory:')

    def test_missing_parent_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                DurableCommandReplayGate(str(Path(d) / 'missing' / 'commands.sqlite'))

if __name__ == '__main__':
    unittest.main()
