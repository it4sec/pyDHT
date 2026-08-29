import asyncio
import hashlib
import ipaddress
import struct
import unittest
from unittest.mock import patch

import config
from includes import bencode, debug
from includes.dht import (
    CandidateManager,
    DHTNode,
    MAX_DHT_RESPONSE_BYTES,
    TokenManager,
    compact_node,
    compact_peer,
    dht_key_text,
    endpoint_allowed,
    parse_compact_nodes,
    parse_compact_peer,
)


class FakeTransport:
    def __init__(self):
        self.sent = []
    def sendto(self, data, endpoint):
        self.sent.append((data, endpoint))
    def close(self):
        pass


class DHTBasicTests(unittest.TestCase):
    def test_client_version_exact_value(self):
        self.assertEqual(config.DHT_CLIENT_VERSION, "qB7K")
        debug.validate_config()

    def test_invalid_client_version_rejected(self):
        with patch.object(config, "DHT_CLIENT_VERSION", "abc"):
            with self.assertRaises(debug.ConfigurationError):
                debug.validate_config()

    def test_bep51_response_interval_validation(self):
        with patch.object(config, "DHT_BEP51_RESPONSE_INTERVAL", 21601):
            with self.assertRaises(debug.ConfigurationError):
                debug.validate_config()

    def test_compact_peer_roundtrip(self):
        raw = compact_peer(("8.8.8.8", 6881))
        self.assertEqual(len(raw), 6)
        self.assertEqual(parse_compact_peer(raw), ("8.8.8.8", 6881))

    def test_compact_node_roundtrip(self):
        node_id = b"a" * 20
        raw = compact_node(node_id, ("1.1.1.1", 1234))
        self.assertEqual(parse_compact_nodes(raw), [(node_id, "1.1.1.1", 1234)])

    def test_endpoint_policy_rejects_private_default(self):
        with patch.object(config, "ALLOW_NON_GLOBAL_ENDPOINTS", False):
            self.assertFalse(endpoint_allowed("192.168.1.2", 6881))
            self.assertFalse(endpoint_allowed("127.0.0.1", 6881))
            self.assertTrue(endpoint_allowed("8.8.8.8", 6881))

    def test_endpoint_policy_override(self):
        with patch.object(config, "ALLOW_NON_GLOBAL_ENDPOINTS", True):
            self.assertTrue(endpoint_allowed("192.168.1.2", 6881))

    def test_dht_key_text_is_not_btih(self):
        self.assertEqual(dht_key_text(b"\x01" * 20), "dht20:" + "01" * 20)

    def test_token_bound_to_ip(self):
        now = [0]
        tm = TokenManager(clock_ns=lambda: now[0])
        token = tm.issue("8.8.8.8")
        self.assertTrue(tm.validate("8.8.8.8", token))
        self.assertFalse(tm.validate("1.1.1.1", token))

    def test_token_expires_after_validity(self):
        now = [0]
        with patch.object(config, "DHT_TOKEN_ROTATION_INTERVAL", 10), patch.object(config, "DHT_TOKEN_VALIDITY", 20):
            tm = TokenManager(clock_ns=lambda: now[0])
            token = tm.issue("8.8.8.8")
            now[0] = 21_000_000_000
            self.assertFalse(tm.validate("8.8.8.8", token))


class DHTAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.events = []
        self.q = asyncio.Queue(maxsize=4)
        self.manager = CandidateManager(self.q)
        self.node = DHTNode(b"L" * 20, self.manager, lambda r: self.events.append(r) or True)
        self.node.transport = FakeTransport()
        self.node.local_ips = {"127.0.0.1"}

    async def test_candidate_duplicate_merges_peer_hint(self):
        key = b"K" * 20
        self.assertTrue(self.manager.submit(key, "get_peers"))
        self.assertTrue(self.manager.submit(key, "announce_peer", ("8.8.8.8", 6881, False)))
        self.assertEqual(self.q.qsize(), 1)
        self.assertIn(("8.8.8.8", 6881, False), self.manager.state_for(key).peer_hints)

    async def test_queue_full_rolls_back_reservation(self):
        q = asyncio.Queue(maxsize=1)
        m = CandidateManager(q)
        self.assertTrue(m.submit(b"A" * 20, "x"))
        self.assertFalse(m.submit(b"B" * 20, "x"))
        self.assertNotIn(b"B" * 20, m.states)

    async def test_outbound_query_includes_fixed_v(self):
        with patch.object(config, "ALLOW_NON_GLOBAL_ENDPOINTS", True), patch.object(config, "DHT_QUERY_TIMEOUT", 0.01):
            with self.assertRaises(asyncio.TimeoutError):
                await self.node.query(("127.0.0.2", 9999), b"ping", {})
        raw, _ = self.node.transport.sent[0]
        msg = bencode.decode(raw, max_depth=8, max_items=100, max_string_length=1000)
        self.assertEqual(msg[b"v"], b"qB7K")

    async def test_response_endpoint_mismatch_does_not_complete(self):
        with patch.object(config, "ALLOW_NON_GLOBAL_ENDPOINTS", True), patch.object(config, "DHT_QUERY_TIMEOUT", 0.03):
            task = asyncio.create_task(self.node.query(("127.0.0.2", 9999), b"ping", {}))
            await asyncio.sleep(0)
            raw, _ = self.node.transport.sent[0]
            query = bencode.decode(raw, max_depth=8, max_items=100, max_string_length=1000)
            response = {b"t": query[b"t"], b"y": b"r", b"v": b"XX01", b"r": {b"id": b"R" * 20}}
            self.node.handle_datagram(bencode.encode(response), ("127.0.0.3", 9999))
            with self.assertRaises(asyncio.TimeoutError):
                await task
        self.assertTrue(any(e.get("event") == "response_endpoint_mismatch" for e in self.events))

    async def test_known_node_id_mismatch_does_not_complete(self):
        with patch.object(config, "ALLOW_NON_GLOBAL_ENDPOINTS", True), patch.object(config, "DHT_QUERY_TIMEOUT", 0.03):
            task = asyncio.create_task(self.node.query(("127.0.0.2", 9999), b"ping", {}, expected_node_id=b"E" * 20))
            await asyncio.sleep(0)
            raw, _ = self.node.transport.sent[0]
            query = bencode.decode(raw, max_depth=8, max_items=100, max_string_length=1000)
            response = {b"t": query[b"t"], b"y": b"r", b"v": b"XX01", b"r": {b"id": b"R" * 20}}
            self.node.handle_datagram(bencode.encode(response), ("127.0.0.2", 9999))
            with self.assertRaises(asyncio.TimeoutError):
                await task
        self.assertTrue(any(e.get("event") == "response_node_id_mismatch" for e in self.events))

    async def test_incoming_bep51_interval_and_size(self):
        with patch.object(config, "ALLOW_NON_GLOBAL_ENDPOINTS", True):
            for i in range(100):
                self.node.peer_store.add(bytes([i % 256]) * 20, ("127.0.0.2", 6000 + i))
        args = {b"id": b"R" * 20, b"target": b"T" * 20}
        response = self.node._incoming_sample_infohashes(args, "x")
        self.assertEqual(response[b"interval"], 300)
        packet = self.node._base(b"aa", b"r") | {b"r": response}
        self.assertLessEqual(len(bencode.encode(packet)), MAX_DHT_RESPONSE_BYTES)
        self.assertIn(b"samples", response)

    async def test_invalid_announce_token_is_recorded_but_not_stored(self):
        args = {b"id": b"R" * 20, b"info_hash": b"I" * 20, b"port": 6881, b"token": b"bad"}
        from includes.dht import KRPCError
        with self.assertRaises(KRPCError):
            self.node._incoming_announce_peer(args, ("8.8.8.8", 50000), {}, "ex")
        rec = [e for e in self.events if e.get("event") == "announce_peer"][-1]
        self.assertFalse(rec["token_valid"])
        self.assertNotIn("token", rec)

    async def test_read_only_ignores_incoming_query(self):
        transport = self.node.transport
        msg = {b"t": b"aa", b"y": b"q", b"v": b"XX01", b"q": b"ping", b"a": {b"id": b"R" * 20}}
        with patch.object(config, "DHT_READ_ONLY", True):
            self.node.handle_datagram(bencode.encode(msg), ("8.8.8.8", 6881))
        self.assertEqual(transport.sent, [])


if __name__ == "__main__":
    unittest.main()
