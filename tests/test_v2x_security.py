import unittest
from datetime import datetime, timedelta, timezone

import v2x_protocol as v2x


KEY = "K" * 48
OTHER_KEY = "M" * 48


class V2XSecurityTests(unittest.TestCase):
    def setUp(self):
        self._old_oqs = v2x.oqs
        v2x.oqs = None

    def tearDown(self):
        v2x.oqs = self._old_oqs

    def _establish_psk_session(self):
        client = v2x.DynamicCryptoAgilityLayer("CAR1", shared_secret=KEY)
        server = v2x.DynamicCryptoAgilityLayer("hub-peer:CAR1", shared_secret=KEY)
        hello_payload = client.handshake_hello_payload()
        self.assertTrue(server.pin_peer_identity(hello_payload))
        context = v2x._make_nonce()
        ack = server.accept_handshake_as_server(hello_payload, session_context=context)
        self.assertEqual(ack["hs_mode"], v2x.DynamicCryptoAgilityLayer.HS_PSK)
        self.assertTrue(client.complete_handshake_as_client(ack, session_context=context))
        self.assertEqual(client._session_id, server._session_id)
        self.assertEqual(client._session_key, server._session_key)
        return client, server

    def test_nonce_is_128_bit_random(self):
        first = v2x._make_nonce("same")
        second = v2x._make_nonce("same")
        self.assertEqual(len(first), 32)
        self.assertNotEqual(first, second)

    def test_short_secret_is_rejected(self):
        with self.assertRaises(RuntimeError):
            v2x.DynamicCryptoAgilityLayer("CAR1", shared_secret="short")

    def test_psk_session_is_consistent_on_both_sides(self):
        self._establish_psk_session()

    def test_data_plane_sender_binding_and_replay(self):
        client, server = self._establish_psk_session()
        message = v2x._new_message(
            v2x.V2XMessageType.V2V_TELEMETRY,
            "CAR1",
            "vehicle",
            {"speed": 1},
        )
        message["security"] = client.sign_message(message)
        replay_cache = {}
        self.assertTrue(
            server.verify_message(
                message,
                expected_sender_id="CAR1",
                replay_cache=replay_cache,
            )
        )
        self.assertFalse(
            server.verify_message(
                message,
                expected_sender_id="CAR1",
                replay_cache=replay_cache,
            )
        )

        fresh = dict(message)
        fresh["nonce"] = v2x._make_nonce()
        fresh.pop("security")
        fresh["security"] = client.sign_message(fresh)
        self.assertFalse(
            server.verify_message(
                fresh,
                expected_sender_id="CAR2",
                replay_cache={},
            )
        )

    def test_stale_data_plane_message_is_rejected(self):
        client, server = self._establish_psk_session()
        message = v2x._new_message(v2x.V2XMessageType.ALERT, "CAR1", "vehicle", {})
        message["timestamp"] = (
            datetime.now(timezone.utc) - timedelta(minutes=2)
        ).isoformat()
        message["security"] = client.sign_message(message)
        self.assertFalse(
            server.verify_message(
                message,
                expected_sender_id="CAR1",
                replay_cache={},
                max_skew_sec=15,
            )
        )

    def test_hub_forwarding_is_authenticated_and_tamper_evident(self):
        client, server = self._establish_psk_session()
        message = v2x._new_message(
            v2x.V2XMessageType.ALERT,
            "CAR2",
            "vehicle",
            {"risk": "high"},
        )
        message["hub_security"] = server.sign_forwarded_message(message)
        replay_cache = {}
        self.assertTrue(
            client.verify_forwarded_message(message, replay_cache=replay_cache)
        )
        self.assertFalse(
            client.verify_forwarded_message(message, replay_cache=replay_cache)
        )

        tampered = v2x._new_message(
            v2x.V2XMessageType.ALERT,
            "CAR2",
            "vehicle",
            {"risk": "high"},
        )
        tampered["hub_security"] = server.sign_forwarded_message(tampered)
        tampered["payload"]["risk"] = "low"
        self.assertFalse(
            client.verify_forwarded_message(tampered, replay_cache={})
        )

    def test_authenticated_hello_and_replay_rejection(self):
        hub = v2x.V2XHub(node_key_registry={"CAR1": KEY})
        node = v2x.V2XNode("CAR1", "vehicle", node_secret=KEY)
        hello = node._build_hello_message()
        self.assertEqual(hub._authenticate_hello(hello), KEY)
        self.assertIsNone(hub._authenticate_hello(hello))

        forged = dict(hello)
        forged["nonce"] = v2x._make_nonce()
        forged["hello_mac"] = v2x._auth_mac(OTHER_KEY, forged, "hello_mac")
        self.assertIsNone(hub._authenticate_hello(forged))

    def test_unknown_node_is_rejected_by_registry(self):
        hub = v2x.V2XHub(node_key_registry={"CAR1": KEY})
        unknown = v2x.V2XNode("CAR2", "vehicle", node_secret=OTHER_KEY)
        self.assertIsNone(hub._authenticate_hello(unknown._build_hello_message()))

    def test_ack_is_bound_to_requested_node(self):
        node = v2x.V2XNode("CAR1", "vehicle", node_secret=KEY)
        ack = v2x._new_message(
            v2x.V2XMessageType.HELLO_ACK,
            "v2x_hub",
            "infrastructure",
            {"peer_node_id": "CAR1", "handshake": {"hs_mode": "PSK"}},
        )
        ack["ack_mac"] = v2x._auth_mac(KEY, ack, "ack_mac")
        self.assertTrue(node._verify_ack(ack))
        ack["payload"]["peer_node_id"] = "CAR2"
        self.assertFalse(node._verify_ack(ack))


if __name__ == "__main__":
    unittest.main()
