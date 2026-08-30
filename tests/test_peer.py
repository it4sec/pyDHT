import asyncio
import hashlib
import struct
import unittest
from unittest.mock import AsyncMock, patch

import config
from includes import bencode
from includes.peer import (
    BEP9_BLOCK_SIZE,
    BT_EXTENDED_MESSAGE_ID,
    LOCAL_UT_METADATA_ID,
    MetadataResult,
    PeerClient,
    PeerError,
    build_handshake,
    parse_extension_handshake,
    parse_handshake,
    parse_metadata_message,
)


class FakeWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass

    def get_extra_info(self, name):
        if name == "sockname":
            return ("192.0.2.1", 50000)
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def metadata_data_frame(piece, total_size, payload, ext_id=LOCAL_UT_METADATA_ID):
    header = bencode.encode({b"msg_type": 1, b"piece": piece, b"total_size": total_size})
    body = bytes([BT_EXTENDED_MESSAGE_ID, ext_id]) + header + payload
    return struct.pack("!I", len(body)) + body


class PeerCodecTests(unittest.TestCase):
    def test_handshake_roundtrip(self):
        info = b"I" * 20
        peer_id = b"P" * 20
        parsed = parse_handshake(build_handshake(info, peer_id), info)
        self.assertTrue(parsed.extension_protocol)
        self.assertTrue(parsed.dht_capability)
        self.assertEqual(parsed.peer_id, peer_id)

    def test_handshake_rejects_wrong_hash(self):
        with self.assertRaises(PeerError):
            parse_handshake(build_handshake(b"I" * 20, b"P" * 20), b"X" * 20)

    def test_extension_mapping_is_connection_specific(self):
        ext = parse_extension_handshake(bencode.encode({b"m": {b"ut_metadata": 7}, b"metadata_size": 100, b"v": b"Client"}))
        self.assertEqual(ext.ut_metadata_id, 7)
        self.assertEqual(ext.metadata_size, 100)
        self.assertEqual(ext.peer_client, "Client")

    def test_extension_handshake_accepts_unsorted_peer_dictionary(self):
        raw = b"d13:metadata_sizei100e1:md11:ut_metadatai7ee1:v6:Cliente"
        ext = parse_extension_handshake(raw)
        self.assertEqual(ext.ut_metadata_id, 7)
        self.assertEqual(ext.metadata_size, 100)
        self.assertEqual(ext.peer_client, "Client")

    def test_metadata_header_accepts_unsorted_peer_dictionary(self):
        raw = b"d5:piecei0e8:msg_typei1e10:total_sizei3eeabc"
        header, payload = parse_metadata_message(raw, metadata_size=3, expected_piece_count=1)
        self.assertEqual(header[b"piece"], 0)
        self.assertEqual(payload, b"abc")

    def test_extension_rejects_oversized_metadata(self):
        with self.assertRaises(PeerError):
            parse_extension_handshake(bencode.encode({b"m": {b"ut_metadata": 1}, b"metadata_size": config.MAX_METADATA_SIZE + 1}))

    def test_metadata_piece_size_validation(self):
        size = BEP9_BLOCK_SIZE + 3
        header = bencode.encode({b"msg_type": 1, b"piece": 0, b"total_size": size})
        with self.assertRaises(PeerError):
            parse_metadata_message(header + b"x", metadata_size=size, expected_piece_count=2)

    def test_last_metadata_piece_may_be_short(self):
        size = BEP9_BLOCK_SIZE + 3
        header = bencode.encode({b"msg_type": 1, b"piece": 1, b"total_size": size})
        parsed, payload = parse_metadata_message(header + b"abc", metadata_size=size, expected_piece_count=2)
        self.assertEqual(parsed[b"piece"], 1)
        self.assertEqual(payload, b"abc")


class PeerAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_out_of_order_metadata_assembly(self):
        events = []
        client = PeerClient(asyncio.Semaphore(1), lambda r: events.append(r) or True, peer_id=b"P" * 20)
        metadata = b"a" * BEP9_BLOCK_SIZE + b"xyz"
        reader = asyncio.StreamReader()
        reader.feed_data(metadata_data_frame(1, len(metadata), b"xyz"))
        reader.feed_data(metadata_data_frame(0, len(metadata), b"a" * BEP9_BLOCK_SIZE))
        writer = FakeWriter()
        raw = await client._download_metadata(reader, writer, "s", ("8.8.8.8", 1), "dht20:" + "00" * 20, 5, len(metadata))
        self.assertEqual(raw, metadata)
        self.assertTrue(any(e.get("event") == "metadata_message" for e in events))

    async def test_conflicting_duplicate_piece_rejected(self):
        events = []
        client = PeerClient(asyncio.Semaphore(1), lambda r: events.append(r) or True, peer_id=b"P" * 20)
        metadata = b"a" * BEP9_BLOCK_SIZE + b"xyz"
        reader = asyncio.StreamReader()
        reader.feed_data(metadata_data_frame(0, len(metadata), b"a" * BEP9_BLOCK_SIZE))
        reader.feed_data(metadata_data_frame(0, len(metadata), b"b" * BEP9_BLOCK_SIZE))
        writer = FakeWriter()
        with self.assertRaises(PeerError):
            await client._download_metadata(reader, writer, "s", ("8.8.8.8", 1), "dht20:" + "00" * 20, 5, len(metadata))

    async def test_disconnect_before_bt_handshake_is_normalized(self):
        events = []
        client = PeerClient(asyncio.Semaphore(1), lambda r: events.append(r) or True, peer_id=b"P" * 20)
        reader = asyncio.StreamReader()
        reader.feed_eof()
        writer = FakeWriter()
        with patch("includes.peer.asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
            with self.assertRaises(PeerError) as caught:
                await client.fetch_metadata(("8.8.8.8", 6881), b"I" * 20)
        self.assertEqual(caught.exception.category, "peer_disconnected")
        self.assertEqual(caught.exception.stage, "bt_handshake")
        self.assertTrue(any(e.get("failure_category") == "peer_disconnected" for e in events))

    async def test_disconnect_during_extension_handshake_is_normalized(self):
        events = []
        info_hash = b"I" * 20
        client = PeerClient(asyncio.Semaphore(1), lambda r: events.append(r) or True, peer_id=b"P" * 20)
        reader = asyncio.StreamReader()
        reader.feed_data(build_handshake(info_hash, b"R" * 20))
        reader.feed_eof()
        writer = FakeWriter()
        with patch("includes.peer.asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
            with self.assertRaises(PeerError) as caught:
                await client.fetch_metadata(("8.8.8.8", 6881), info_hash)
        self.assertEqual(caught.exception.category, "peer_disconnected")
        self.assertEqual(caught.exception.stage, "extension_handshake")

    async def test_disconnect_during_metadata_is_normalized(self):
        events = []
        info_hash = b"I" * 20
        client = PeerClient(asyncio.Semaphore(1), lambda r: events.append(r) or True, peer_id=b"P" * 20)
        ext_payload = bencode.encode({b"m": {b"ut_metadata": 7}, b"metadata_size": 10})
        ext_body = bytes([BT_EXTENDED_MESSAGE_ID, 0]) + ext_payload
        reader = asyncio.StreamReader()
        reader.feed_data(build_handshake(info_hash, b"R" * 20))
        reader.feed_data(struct.pack("!I", len(ext_body)) + ext_body)
        reader.feed_eof()
        writer = FakeWriter()
        with patch("includes.peer.asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
            with self.assertRaises(PeerError) as caught:
                await client.fetch_metadata(("8.8.8.8", 6881), info_hash)
        self.assertEqual(caught.exception.category, "peer_disconnected")
        self.assertEqual(caught.exception.stage, "metadata")

    async def test_malformed_extension_bencode_is_normalized(self):
        events = []
        info_hash = b"I" * 20
        client = PeerClient(asyncio.Semaphore(1), lambda r: events.append(r) or True, peer_id=b"P" * 20)
        ext_body = bytes([BT_EXTENDED_MESSAGE_ID, 0]) + b"d1:m"
        reader = asyncio.StreamReader()
        reader.feed_data(build_handshake(info_hash, b"R" * 20))
        reader.feed_data(struct.pack("!I", len(ext_body)) + ext_body)
        reader.feed_eof()
        writer = FakeWriter()
        with patch("includes.peer.asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
            with self.assertRaises(PeerError) as caught:
                await client.fetch_metadata(("8.8.8.8", 6881), info_hash)
        self.assertEqual(caught.exception.category, "extension_handshake_invalid")
        self.assertEqual(caught.exception.stage, "extension_handshake")


class CandidateProcessingTests(unittest.IsolatedAsyncioTestCase):
    class FakeDB:
        def __init__(self):
            self.state = {"state": "new", "attempts": 0, "next_attempt_at": None}
            self.persisted = False

        async def upsert_candidate_seen(self, dht_key, first_seen, last_seen):
            return dict(self.state)

        async def mark_fetching(self, dht_key, now_ns):
            self.state.update({"state": "fetching", "attempts": self.state["attempts"] + 1, "next_attempt_at": None})
            return True

        async def candidate_state(self, dht_key):
            return dict(self.state)

        async def mark_fetch_failed(self, dht_key, error, now_ns, next_attempt_ns):
            self.state.update({"state": "fetch_failed", "last_error": error, "next_attempt_at": next_attempt_ns})

        async def persist_torrent(self, torrent, dht_key, notification, now_ns):
            self.persisted = True
            self.state.update({"state": "complete", "torrent_uid": torrent.torrent_uid})

    class FakeDHT:
        def __init__(self, peers):
            self.local_ips = set()
            self.peers = peers

        async def iterative_get_peers(self, key):
            return list(self.peers)

    class SequencePeerClient:
        def __init__(self, raw_info, fail_all=False):
            self.raw_info = raw_info
            self.fail_all = fail_all
            self.calls = []

        async def fetch_metadata(self, endpoint, key):
            self.calls.append(endpoint)
            if self.fail_all or len(self.calls) == 1:
                raise PeerError("remote peer closed", category="peer_disconnected", stage="bt_handshake")
            return MetadataResult(self.raw_info, "session", endpoint, 1.0, 1.0)

    async def _setup_candidate(self, raw_info):
        from includes.dht import CandidateManager
        queue = asyncio.Queue(maxsize=4)
        manager = CandidateManager(queue)
        key = hashlib.sha1(raw_info).digest()
        manager.submit(key, "test", ("8.8.8.8", 6881, False))
        return key, manager

    async def test_first_peer_failure_second_peer_success(self):
        from main import _process_candidate
        raw_info = bencode.encode({b"length": 1, b"name": b"x", b"piece length": 16384})
        key, manager = await self._setup_candidate(raw_info)
        db = self.FakeDB()
        peer_client = self.SequencePeerClient(raw_info)
        dht = self.FakeDHT([("1.1.1.1", 6881)])
        await _process_candidate(0, key, manager, db, dht, peer_client)
        self.assertEqual(peer_client.calls, [("8.8.8.8", 6881), ("1.1.1.1", 6881)])
        self.assertTrue(db.persisted)
        self.assertEqual(db.state["state"], "complete")

    async def test_all_expected_peer_failures_become_fetch_failed(self):
        from main import _process_candidate
        raw_info = bencode.encode({b"length": 1, b"name": b"x", b"piece length": 16384})
        key, manager = await self._setup_candidate(raw_info)
        db = self.FakeDB()
        peer_client = self.SequencePeerClient(raw_info, fail_all=True)
        dht = self.FakeDHT([("1.1.1.1", 6881)])
        await _process_candidate(0, key, manager, db, dht, peer_client)
        self.assertEqual(db.state["state"], "fetch_failed")
        self.assertIsNone(manager.state_for(key))
        self.assertIn("peer_disconnected", db.state["last_error"])


if __name__ == "__main__":
    unittest.main()
