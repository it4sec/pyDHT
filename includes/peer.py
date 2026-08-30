"""BitTorrent TCP peer-wire, BEP-10 and BEP-9 metadata exchange."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
import socket
import struct
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

import config
from . import bencode
from .dht import dht_key_text

LOG = logging.getLogger(__name__)

BT_PROTOCOL = b"BitTorrent protocol"
BT_HANDSHAKE_BYTES = 68
BT_EXTENDED_MESSAGE_ID = 20
BT_PORT_MESSAGE_ID = 9
BEP9_BLOCK_SIZE = 16 * 1024
LOCAL_UT_METADATA_ID = 1


class PeerError(RuntimeError):
    """Expected remote peer/network failure normalized at the peer boundary."""

    def __init__(self, message: str, *, category: str = "peer_error", stage: str | None = None):
        super().__init__(message)
        self.category = category
        self.stage = stage


class MetadataRejected(PeerError):
    def __init__(self, message: str):
        super().__init__(message, category="metadata_rejected", stage="metadata")


class MetadataHashMismatch(PeerError):
    def __init__(self, message: str):
        super().__init__(message, category="metadata_hash_mismatch", stage="metadata")


@dataclass(slots=True, frozen=True)
class PeerHandshake:
    protocol_identifier: bytes
    reserved: bytes
    info_hash: bytes
    peer_id: bytes

    @property
    def extension_protocol(self) -> bool:
        return bool(self.reserved[5] & 0x10)

    @property
    def dht_capability(self) -> bool:
        return bool(self.reserved[7] & 0x01)


@dataclass(slots=True, frozen=True)
class ExtensionHandshake:
    mapping: dict[bytes, int]
    ut_metadata_id: int | None
    metadata_size: int | None
    peer_listen_port: int | None
    peer_client: str | None
    yourip: str | None
    advertised_ipv4: str | None
    advertised_ipv6: str | None
    reqq: int | None


@dataclass(slots=True, frozen=True)
class MetadataResult:
    raw_info: bytes
    peer_session_id: str
    remote_endpoint: tuple[str, int]
    connect_ms: float
    transfer_ms: float


def build_handshake(info_hash: bytes, peer_id: bytes) -> bytes:
    if len(info_hash) != 20 or len(peer_id) != 20:
        raise ValueError("info_hash and peer_id must be 20 bytes")
    reserved = bytearray(8)
    reserved[5] |= 0x10  # BEP-10
    reserved[7] |= 0x01  # DHT/PORT capability
    return bytes([len(BT_PROTOCOL)]) + BT_PROTOCOL + bytes(reserved) + info_hash + peer_id


def parse_handshake(data: bytes, expected_info_hash: bytes) -> PeerHandshake:
    if len(data) != BT_HANDSHAKE_BYTES:
        raise PeerError("invalid BitTorrent handshake length", category="handshake_invalid", stage="bt_handshake")
    pstrlen = data[0]
    if pstrlen != len(BT_PROTOCOL) or data[1:20] != BT_PROTOCOL:
        raise PeerError("unexpected BitTorrent protocol identifier", category="handshake_invalid", stage="bt_handshake")
    reserved = data[20:28]
    info_hash = data[28:48]
    peer_id = data[48:68]
    if info_hash != expected_info_hash:
        raise PeerError("wire infohash mismatch", category="handshake_invalid", stage="bt_handshake")
    return PeerHandshake(BT_PROTOCOL, reserved, info_hash, peer_id)


def _compact_ip(value: Any) -> str | None:
    if not isinstance(value, bytes):
        return None
    try:
        if len(value) == 4:
            return str(ipaddress.IPv4Address(value))
        if len(value) == 16:
            return str(ipaddress.IPv6Address(value))
    except ipaddress.AddressValueError:
        pass
    return None


def parse_extension_handshake(payload: bytes) -> ExtensionHandshake:
    try:
        value = bencode.decode(
            payload,
            max_depth=config.MAX_BENCODE_DEPTH,
            max_items=config.MAX_BENCODE_ITEMS,
            max_string_length=config.MAX_BENCODE_STRING_LENGTH,
            require_sorted_keys=False,
        )
    except bencode.BencodeError as exc:
        raise PeerError(
            "invalid BEP-10 extension handshake bencode",
            category="extension_handshake_invalid",
            stage="extension_handshake",
        ) from exc
    if not isinstance(value, dict):
        raise PeerError(
            "BEP-10 handshake must be a dictionary",
            category="extension_handshake_invalid",
            stage="extension_handshake",
        )
    raw_mapping = value.get(b"m", {})
    mapping: dict[bytes, int] = {}
    if isinstance(raw_mapping, dict):
        for name, ext_id in raw_mapping.items():
            if isinstance(name, bytes) and isinstance(ext_id, int) and 0 <= ext_id <= 255:
                mapping[name] = ext_id
    ut_id = mapping.get(b"ut_metadata")
    if ut_id == 0:
        ut_id = None
    size = value.get(b"metadata_size")
    if size is not None and (not isinstance(size, int) or size <= 0 or size > config.MAX_METADATA_SIZE):
        raise PeerError(
            "invalid or excessive metadata_size",
            category="extension_handshake_invalid",
            stage="extension_handshake",
        )
    port = value.get(b"p")
    if port is not None and (not isinstance(port, int) or not (1 <= port <= 65535)):
        port = None
    client = value.get(b"v")
    client_text = client.decode("utf-8", errors="replace")[: config.MAX_EVIDENCE_TEXT_LENGTH] if isinstance(client, bytes) else None
    reqq = value.get(b"reqq")
    if reqq is not None and (not isinstance(reqq, int) or reqq < 0):
        reqq = None
    return ExtensionHandshake(
        mapping=mapping,
        ut_metadata_id=ut_id,
        metadata_size=size,
        peer_listen_port=port,
        peer_client=client_text,
        yourip=_compact_ip(value.get(b"yourip")),
        advertised_ipv4=_compact_ip(value.get(b"ipv4")),
        advertised_ipv6=_compact_ip(value.get(b"ipv6")),
        reqq=reqq,
    )


def build_extended_handshake() -> bytes:
    payload = bencode.encode({b"m": {b"ut_metadata": LOCAL_UT_METADATA_ID}, b"v": config.PEER_CLIENT_NAME.encode("utf-8"), b"reqq": config.METADATA_REQUEST_PIPELINE})
    body = bytes([BT_EXTENDED_MESSAGE_ID, 0]) + payload
    return struct.pack("!I", len(body)) + body


def build_metadata_request(extension_id: int, piece: int) -> bytes:
    if not (1 <= extension_id <= 255) or piece < 0:
        raise ValueError("invalid extension ID or piece")
    payload = bencode.encode({b"msg_type": 0, b"piece": piece})
    body = bytes([BT_EXTENDED_MESSAGE_ID, extension_id]) + payload
    return struct.pack("!I", len(body)) + body


def build_metadata_reject(extension_id: int, piece: int) -> bytes:
    payload = bencode.encode({b"msg_type": 2, b"piece": piece})
    body = bytes([BT_EXTENDED_MESSAGE_ID, extension_id]) + payload
    return struct.pack("!I", len(body)) + body


def parse_metadata_message(payload: bytes, *, metadata_size: int, expected_piece_count: int) -> tuple[dict[bytes, Any], bytes]:
    try:
        header, consumed = bencode.decode_prefix(
            payload,
            max_depth=config.MAX_BENCODE_DEPTH,
            max_items=config.MAX_BENCODE_ITEMS,
            max_string_length=config.MAX_BENCODE_STRING_LENGTH,
            require_sorted_keys=False,
        )
    except bencode.BencodeError as exc:
        raise PeerError(
            "invalid BEP-9 metadata message bencode",
            category="metadata_invalid",
            stage="metadata",
        ) from exc
    if not isinstance(header, dict):
        raise PeerError("BEP-9 message header must be a dictionary", category="metadata_invalid", stage="metadata")
    msg_type = header.get(b"msg_type")
    piece = header.get(b"piece")
    if msg_type not in {0, 1, 2} or not isinstance(piece, int) or not (0 <= piece < expected_piece_count):
        raise PeerError("invalid BEP-9 message type or piece", category="metadata_invalid", stage="metadata")
    trailing = payload[consumed:]
    if msg_type == 1:
        total_size = header.get(b"total_size")
        if total_size != metadata_size:
            raise PeerError("BEP-9 total_size inconsistent with metadata_size", category="metadata_invalid", stage="metadata")
        expected_size = min(BEP9_BLOCK_SIZE, metadata_size - piece * BEP9_BLOCK_SIZE)
        if len(trailing) != expected_size:
            raise PeerError("invalid BEP-9 piece size", category="metadata_invalid", stage="metadata")
    elif trailing:
        raise PeerError("unexpected payload on BEP-9 request/reject", category="metadata_invalid", stage="metadata")
    return header, trailing



class PeerClient:
    def __init__(self, connection_semaphore: asyncio.Semaphore, emit: Callable[[dict[str, Any]], bool], peer_id: bytes | None = None):
        self.connection_semaphore = connection_semaphore
        self.emit = emit
        self.peer_id = peer_id or self._make_peer_id()

    @staticmethod
    def _make_peer_id() -> bytes:
        prefix = config.PEER_ID_PREFIX.encode("ascii")
        return (prefix + os.urandom(20 - len(prefix)))[:20]

    async def fetch_metadata(self, endpoint: tuple[str, int], info_hash: bytes) -> MetadataResult:
        session_id = str(uuid.uuid4())
        dht_key = dht_key_text(info_hash)
        async with self.connection_semaphore:
            try:
                async with asyncio.timeout(config.PEER_SESSION_TIMEOUT):
                    return await self._fetch(session_id, endpoint, info_hash, dht_key)
            except asyncio.CancelledError:
                raise
            except TimeoutError as exc:
                normalized = PeerError(
                    "peer session deadline exceeded",
                    category="session_timeout",
                    stage="session",
                )
                self._failure(session_id, endpoint, dht_key, normalized.category, str(normalized), normalized.stage)
                raise normalized from exc
            except PeerError as exc:
                self._failure(session_id, endpoint, dht_key, exc.category, str(exc), exc.stage)
                raise
            except bencode.BencodeError as exc:
                normalized = PeerError(
                    "malformed peer bencode",
                    category="protocol_invalid",
                    stage="session",
                )
                self._failure(session_id, endpoint, dht_key, normalized.category, str(normalized), normalized.stage)
                raise normalized from exc
            except (asyncio.IncompleteReadError, OSError, ConnectionError, BrokenPipeError) as exc:
                normalized = PeerError(
                    "peer connection closed or failed",
                    category="peer_io_error",
                    stage="session",
                )
                self._failure(session_id, endpoint, dht_key, normalized.category, str(exc), normalized.stage)
                raise normalized from exc

    async def _fetch(self, session_id: str, endpoint: tuple[str, int], info_hash: bytes, dht_key: str) -> MetadataResult:
        started = time.monotonic_ns()
        stage = "connect"
        writer: asyncio.StreamWriter | None = None
        try:
            peer_ip = ipaddress.ip_address(endpoint[0])
            family = socket.AF_INET if peer_ip.version == 4 else socket.AF_INET6
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(peer_ip), endpoint[1], family=family),
                config.PEER_CONNECT_TIMEOUT,
            )
            connected = time.monotonic_ns()
            local = writer.get_extra_info("sockname")

            stage = "bt_handshake"
            writer.write(build_handshake(info_hash, self.peer_id))
            await writer.drain()
            raw_handshake = await asyncio.wait_for(
                reader.readexactly(BT_HANDSHAKE_BYTES),
                config.PEER_HANDSHAKE_TIMEOUT,
            )
            handshake = parse_handshake(raw_handshake, info_hash)
            self.emit({
                "record_type": "peer", "event": "peer_handshake", "peer_session_id": session_id, "peer_transport": "tcp",
                "local_ip": str(local[0]) if local else None, "local_port": int(local[1]) if local else None,
                "remote_ip": endpoint[0], "remote_port": endpoint[1], "wire_info_hash_hex": info_hash.hex(), "dht_key": dht_key,
                "protocol_identifier": handshake.protocol_identifier.decode("ascii"), "reserved_bits_hex": handshake.reserved.hex(),
                "peer_id_hex": handshake.peer_id.hex(), "dht_capability": handshake.dht_capability,
                "extension_protocol": handshake.extension_protocol,
            })
            if not handshake.extension_protocol:
                raise PeerError(
                    "peer does not advertise BEP-10",
                    category="extension_unsupported",
                    stage="extension_handshake",
                )

            stage = "extension_handshake"
            writer.write(build_extended_handshake())
            await writer.drain()
            ext = await self._wait_extension_handshake(
                reader, writer, session_id, endpoint, dht_key, handshake.dht_capability
            )
            if ext.ut_metadata_id is None:
                raise PeerError(
                    "peer does not advertise ut_metadata",
                    category="ut_metadata_unavailable",
                    stage="extension_handshake",
                )
            if ext.metadata_size is None:
                raise PeerError(
                    "peer did not provide metadata_size",
                    category="extension_handshake_invalid",
                    stage="extension_handshake",
                )

            stage = "metadata"
            transfer_start = time.monotonic_ns()
            raw_info = await asyncio.wait_for(
                self._download_metadata(
                    reader,
                    writer,
                    session_id,
                    endpoint,
                    dht_key,
                    ext.ut_metadata_id,
                    ext.metadata_size,
                    min(config.METADATA_REQUEST_PIPELINE, ext.reqq)
                    if isinstance(ext.reqq, int) and ext.reqq > 0
                    else config.METADATA_REQUEST_PIPELINE,
                ),
                config.METADATA_TIMEOUT,
            )
            transfer_end = time.monotonic_ns()
            if hashlib.sha1(raw_info).digest() != info_hash:
                raise MetadataHashMismatch("exact metadata SHA-1 does not match expected DHT key")
            torrent_uid = "btih:" + info_hash.hex()
            self.emit({
                "record_type": "peer", "event": "metadata_success", "peer_session_id": session_id, "dht_key": dht_key,
                "torrent_uid": torrent_uid, "remote_ip": endpoint[0], "remote_port": endpoint[1], "metadata_size": len(raw_info),
                "connect_ms": (connected - started) / 1e6, "transfer_ms": (transfer_end - transfer_start) / 1e6, "hash_valid": True,
            })
            return MetadataResult(
                raw_info,
                session_id,
                endpoint,
                (connected - started) / 1e6,
                (transfer_end - transfer_start) / 1e6,
            )
        except asyncio.CancelledError:
            raise
        except PeerError:
            raise
        except asyncio.TimeoutError as exc:
            if stage == "connect":
                category = "connect_timeout"
                message = "TCP connect timeout"
            elif stage in {"bt_handshake", "extension_handshake"}:
                category = "handshake_timeout"
                message = f"timeout during {stage}"
            else:
                category = "metadata_timeout"
                message = "metadata exchange timeout"
            raise PeerError(message, category=category, stage=stage) from exc
        except asyncio.IncompleteReadError as exc:
            raise PeerError(
                f"peer disconnected during {stage}",
                category="peer_disconnected",
                stage=stage,
            ) from exc
        except (ConnectionError, BrokenPipeError, OSError) as exc:
            if stage == "connect":
                raise PeerError(
                    "TCP connection failed",
                    category="connect_failed",
                    stage=stage,
                ) from exc
            raise PeerError(
                f"peer connection failed during {stage}",
                category="peer_disconnected",
                stage=stage,
            ) from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    async def _wait_extension_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: str,
                                        endpoint: tuple[str, int], dht_key: str, dht_capability: bool) -> ExtensionHandshake:
        deadline = asyncio.get_running_loop().time() + config.PEER_HANDSHAKE_TIMEOUT
        while True:
            timeout = max(0.001, deadline - asyncio.get_running_loop().time())
            length_raw = await asyncio.wait_for(reader.readexactly(4), timeout)
            length = struct.unpack("!I", length_raw)[0]
            if length == 0:
                continue
            if length > config.MAX_PEER_MESSAGE_SIZE:
                raise PeerError("peer message exceeds configured limit", category="extension_handshake_invalid", stage="extension_handshake")
            body = await asyncio.wait_for(reader.readexactly(length), timeout)
            msg_id = body[0]
            if msg_id == BT_PORT_MESSAGE_ID and length == 3 and dht_capability:
                port = struct.unpack("!H", body[1:3])[0]
                self.emit({"record_type": "peer", "event": "peer_dht_port", "peer_session_id": session_id,
                           "peer_dht_udp_port": port, "remote_ip": endpoint[0], "remote_port": endpoint[1], "peer_transport": "tcp"})
                continue
            if msg_id != BT_EXTENDED_MESSAGE_ID or len(body) < 2 or body[1] != 0:
                continue
            ext = parse_extension_handshake(body[2:])
            self._emit_extension(session_id, endpoint, ext)
            return ext

    def _emit_extension(self, session_id: str, endpoint: tuple[str, int], ext: ExtensionHandshake) -> None:
        self.emit({
            "record_type": "peer", "event": "bep10_handshake", "peer_session_id": session_id,
            "remote_ip": endpoint[0], "remote_port": endpoint[1],
            "extension_mapping": {k.decode("utf-8", errors="replace"): v for k, v in ext.mapping.items()},
            "ut_metadata_extension_id": ext.ut_metadata_id, "metadata_size": ext.metadata_size,
            "peer_listen_port": ext.peer_listen_port, "peer_client": ext.peer_client, "yourip": ext.yourip,
            "advertised_ipv4": ext.advertised_ipv4, "advertised_ipv6": ext.advertised_ipv6, "reqq": ext.reqq,
        })

    async def _download_metadata(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: str,
                                 endpoint: tuple[str, int], dht_key: str, remote_ext_id: int, metadata_size: int,
                                 pipeline_limit: int | None = None) -> bytes:
        piece_count = (metadata_size + BEP9_BLOCK_SIZE - 1) // BEP9_BLOCK_SIZE
        pipeline_limit = max(1, min(config.METADATA_REQUEST_PIPELINE, pipeline_limit or config.METADATA_REQUEST_PIPELINE))
        if piece_count <= 0 or metadata_size > config.MAX_METADATA_SIZE:
            raise PeerError("invalid metadata size", category="metadata_invalid", stage="metadata")
        pieces: dict[int, bytes] = {}
        outstanding: set[int] = set()
        next_piece = 0

        async def fill_pipeline() -> None:
            nonlocal next_piece
            while next_piece < piece_count and len(outstanding) < pipeline_limit:
                writer.write(build_metadata_request(remote_ext_id, next_piece))
                self._emit_metadata_message(session_id, endpoint, dht_key, "out", remote_ext_id, 0, next_piece, 0, True, piece_count)
                outstanding.add(next_piece)
                next_piece += 1
            await writer.drain()

        await fill_pipeline()
        while len(pieces) < piece_count:
            length_raw = await reader.readexactly(4)
            length = struct.unpack("!I", length_raw)[0]
            if length == 0:
                continue
            if length > config.MAX_PEER_MESSAGE_SIZE:
                raise PeerError("peer message exceeds configured limit", category="metadata_invalid", stage="metadata")
            body = await reader.readexactly(length)
            msg_id = body[0]
            if msg_id == BT_PORT_MESSAGE_ID and length == 3:
                port = struct.unpack("!H", body[1:3])[0]
                self.emit({"record_type": "peer", "event": "peer_dht_port", "peer_session_id": session_id,
                           "peer_dht_udp_port": port, "remote_ip": endpoint[0], "remote_port": endpoint[1], "peer_transport": "tcp"})
                continue
            if msg_id != BT_EXTENDED_MESSAGE_ID or len(body) < 2:
                continue
            ext_id = body[1]
            if ext_id == 0:
                # BEP-10 permits repeated extension handshakes. Parse/record but do not reset piece state.
                ext = parse_extension_handshake(body[2:])
                self._emit_extension(session_id, endpoint, ext)
                if b"ut_metadata" in ext.mapping:
                    updated_id = ext.mapping[b"ut_metadata"]
                    if updated_id == 0:
                        raise PeerError("peer disabled ut_metadata during metadata exchange", category="ut_metadata_unavailable", stage="metadata")
                    remote_ext_id = updated_id
                continue
            if ext_id == LOCAL_UT_METADATA_ID:
                header, trailing = parse_metadata_message(body[2:], metadata_size=metadata_size, expected_piece_count=piece_count)
                msg_type = header[b"msg_type"]
                piece = header[b"piece"]
                piece_expected = piece in outstanding or piece in pieces
                piece_valid = True
                self._emit_metadata_message(session_id, endpoint, dht_key, "in", ext_id, msg_type, piece, len(trailing), piece_expected, piece_count)
                if msg_type == 0:
                    # We advertise ut_metadata for protocol compatibility but do not serve metadata in this crawler session.
                    writer.write(build_metadata_reject(LOCAL_UT_METADATA_ID, piece))
                    await writer.drain()
                    continue
                if msg_type == 2:
                    if piece in outstanding:
                        raise MetadataRejected(f"peer rejected metadata piece {piece}")
                    continue
                if piece not in outstanding and piece not in pieces:
                    raise PeerError("unsolicited metadata piece", category="metadata_invalid", stage="metadata")
                if piece in pieces:
                    if pieces[piece] != trailing:
                        raise PeerError("conflicting duplicate metadata piece", category="metadata_invalid", stage="metadata")
                    continue
                pieces[piece] = trailing
                outstanding.discard(piece)
                await fill_pipeline()
            # Unknown extension IDs are ignored as required by BEP-9/BEP-10 extensibility.
        raw = b"".join(pieces[i] for i in range(piece_count))
        if len(raw) != metadata_size:
            raise PeerError("assembled metadata length mismatch", category="metadata_invalid", stage="metadata")
        return raw

    def _emit_metadata_message(self, session_id: str, endpoint: tuple[str, int], dht_key: str, direction: str,
                               extension_id: int, msg_type: int, piece: int, payload_bytes: int,
                               piece_expected: bool, piece_count: int) -> None:
        self.emit({
            "record_type": "peer", "event": "metadata_message", "peer_session_id": session_id, "direction": direction,
            "extension_id": extension_id, "msg_type": msg_type, "piece": piece, "payload_bytes": payload_bytes,
            "piece_expected": piece_expected, "piece_valid": True, "metadata_piece_count": piece_count,
            "dht_key": dht_key, "remote_ip": endpoint[0], "remote_port": endpoint[1],
        })

    def _failure(
        self,
        session_id: str,
        endpoint: tuple[str, int],
        dht_key: str,
        category: str,
        detail: str = "",
        stage: str | None = None,
    ) -> None:
        self.emit({
            "record_type": "peer", "event": "metadata_failure", "peer_session_id": session_id, "dht_key": dht_key,
            "remote_ip": endpoint[0], "remote_port": endpoint[1],
            "hash_valid": False if category == "metadata_hash_mismatch" else None,
            "failure_category": category, "failure_stage": stage,
            "detail": detail[: config.MAX_EVIDENCE_TEXT_LENGTH],
        })
