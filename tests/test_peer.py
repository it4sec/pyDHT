import asyncio
import hashlib
import struct
import unittest

import config
from includes import bencode
from includes.peer import (
    BEP9_BLOCK_SIZE,
    BT_EXTENDED_MESSAGE_ID,
    LOCAL_UT_METADATA_ID,
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
    def write(self, data):
        self.data.extend(data)
    async def drain(self):
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


if __name__ == "__main__":
    unittest.main()
