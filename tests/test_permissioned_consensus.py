import unittest
from datetime import datetime, timedelta, timezone

from permissioned_consensus import ConsensusError, PermissionedConsensusEngine, sign_vote


KEYS = {
    "VAL1": "validator-one-secret-material-" + "a" * 32,
    "VAL2": "validator-two-secret-material-" + "b" * 32,
    "VAL3": "validator-three-secret-material-" + "c" * 32,
}
HASH1 = "1" * 64
HASH2 = "2" * 64


class PermissionedConsensusTests(unittest.TestCase):
    def setUp(self):
        self.engine = PermissionedConsensusEngine(KEYS, epoch=7, proposal_ttl_sec=30)
        self.ts = datetime.now(timezone.utc).isoformat()

    def _submit(self, validator, vote=True, proposal_id="P1", proposal_hash=HASH1, epoch=7, ts=None, signature=None):
        ts = ts or self.ts
        if signature is None:
            signature = sign_vote(proposal_id, proposal_hash, validator, vote, epoch, ts, KEYS[validator])
        return self.engine.submit_vote(
            proposal_id=proposal_id,
            proposal_hash=proposal_hash,
            voter_id=validator,
            vote=vote,
            epoch=epoch,
            proposal_timestamp=ts,
            vote_signature=signature,
        )

    def test_quorum_uses_full_validator_set(self):
        first = self._submit("VAL1")
        self.assertEqual(first["status"], "PENDING")
        self.assertEqual(first["quorum_threshold"], 2)
        second = self._submit("VAL2")
        self.assertEqual(second["status"], "ACCEPTED")
        self.assertTrue(second["quorum_reached"])

    def test_duplicate_vote_is_rejected(self):
        self._submit("VAL1")
        with self.assertRaisesRegex(ConsensusError, "DUPLICATE_VOTE"):
            self._submit("VAL1")

    def test_vote_flip_is_rejected(self):
        self._submit("VAL1", True)
        with self.assertRaisesRegex(ConsensusError, "DUPLICATE_VOTE"):
            self._submit("VAL1", False)

    def test_unauthorized_validator_is_rejected(self):
        with self.assertRaisesRegex(ConsensusError, "VALIDATOR_NOT_AUTHORIZED"):
            self.engine.submit_vote(
                proposal_id="P1",
                proposal_hash=HASH1,
                voter_id="OUTSIDER",
                vote=True,
                epoch=7,
                proposal_timestamp=self.ts,
                vote_signature="0" * 64,
            )

    def test_invalid_signature_is_rejected(self):
        with self.assertRaisesRegex(ConsensusError, "INVALID_VOTE_SIGNATURE"):
            self._submit("VAL1", signature="0" * 64)

    def test_proposal_hash_substitution_is_rejected(self):
        self._submit("VAL1", proposal_hash=HASH1)
        signature = sign_vote("P1", HASH2, "VAL2", True, 7, self.ts, KEYS["VAL2"])
        with self.assertRaisesRegex(ConsensusError, "PROPOSAL_HASH_MISMATCH"):
            self._submit("VAL2", proposal_hash=HASH2, signature=signature)

    def test_stale_proposal_is_rejected(self):
        stale = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        with self.assertRaisesRegex(ConsensusError, "STALE_PROPOSAL"):
            self._submit("VAL1", ts=stale)

    def test_wrong_epoch_is_rejected(self):
        signature = sign_vote("P1", HASH1, "VAL1", True, 6, self.ts, KEYS["VAL1"])
        with self.assertRaisesRegex(ConsensusError, "CONSENSUS_EPOCH_MISMATCH"):
            self._submit("VAL1", epoch=6, signature=signature)

    def test_epoch_rotation_clears_old_proposals_and_keys(self):
        self._submit("VAL1")
        new_keys = {
            "VAL2": "rotated-validator-two-" + "d" * 40,
            "VAL4": "rotated-validator-four-" + "e" * 40,
        }
        self.engine.rotate_epoch(8, new_keys)
        self.assertEqual(self.engine.tally("P1")["status"], "UNKNOWN")
        old_sig = sign_vote("P2", HASH1, "VAL1", True, 8, self.ts, KEYS["VAL1"])
        with self.assertRaisesRegex(ConsensusError, "VALIDATOR_NOT_AUTHORIZED"):
            self.engine.submit_vote(
                proposal_id="P2", proposal_hash=HASH1, voter_id="VAL1", vote=True,
                epoch=8, proposal_timestamp=self.ts, vote_signature=old_sig,
            )

    def test_finalized_proposal_rejects_late_vote(self):
        self._submit("VAL1")
        self._submit("VAL2")
        with self.assertRaisesRegex(ConsensusError, "PROPOSAL_FINALIZED"):
            self._submit("VAL3")

    def test_metadata_never_exposes_keys(self):
        metadata = self.engine.metadata()
        self.assertFalse(metadata["secret_values_exposed"])
        text = repr(metadata)
        for key in KEYS.values():
            self.assertNotIn(key, text)


if __name__ == "__main__":
    unittest.main()
