import unittest

import sync_protocol as sp
from replay_security import BoundedReplayCache


KEY = "R" * 48


class ReplayFloodSecurityTests(unittest.TestCase):
    def test_unique_nonce_flood_is_memory_bounded_and_fail_closed(self):
        cache = BoundedReplayCache(max_entries=64)
        accepted = []
        for _ in range(64):
            raw = sp.create_message(sp.MessageType.PING, {}, KEY).decode()
            self.assertIsNotNone(sp.verify_message(raw, KEY, replay_cache=cache, max_skew_sec=30))
            accepted.append(raw)
        self.assertEqual(len(cache), 64)

        overflow = sp.create_message(sp.MessageType.PING, {}, KEY).decode()
        self.assertIsNone(sp.verify_message(overflow, KEY, replay_cache=cache, max_skew_sec=30))
        self.assertEqual(len(cache), 64)
        self.assertGreaterEqual(cache.saturation_rejections, 1)

        # Saturation must never evict a live nonce and make an old message replayable.
        self.assertIsNone(sp.verify_message(accepted[0], KEY, replay_cache=cache, max_skew_sec=30))
        self.assertEqual(len(cache), 64)

    def test_expired_entries_restore_capacity(self):
        cache = BoundedReplayCache(max_entries=16)
        for i in range(16):
            cache[f"nonce-{i}"] = 0.0
        self.assertEqual(len(cache), 16)
        raw = sp.create_message(sp.MessageType.PING, {}, KEY).decode()
        self.assertIsNotNone(sp.verify_message(raw, KEY, replay_cache=cache, max_skew_sec=30))
        self.assertEqual(len(cache), 1)

    def test_sync_server_uses_bounded_handshake_and_session_caches(self):
        server = sp.SyncServer(
            shared_key=KEY,
            vehicle_key_registry={"CAR1": KEY},
        )
        self.assertIsInstance(server._handshake_replay_cache, BoundedReplayCache)

        message = {
            "type": sp.MessageType.HANDSHAKE,
            "payload": {"vehicle_id": "CAR1", "client_version": "2.0"},
            "timestamp": sp._utc_now(),
            "nonce": sp._nonce(),
        }
        message["handshake_mac"] = sp._handshake_mac(KEY, message)
        response = server._process_message(message, "client-1", "")
        self.assertIsNotNone(response)
        self.assertIsInstance(server.clients["client-1"]["replay_cache"], BoundedReplayCache)
        metadata = server.replay_security_metadata()
        self.assertTrue(metadata["fail_closed_on_saturation"])
        self.assertFalse(metadata["evicts_live_nonces"])

    def test_sync_client_uses_bounded_response_cache(self):
        client = sp.SyncClient(vehicle_id="CAR1", shared_key=KEY)
        self.assertIsInstance(client._replay_cache, BoundedReplayCache)
        self.assertEqual(client._replay_cache.max_entries, client.replay_cache_max_entries)


if __name__ == "__main__":
    unittest.main()
