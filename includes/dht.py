"""Mainline DHT (BEP-5/43/51) networking, routing and discovery."""
from __future__ import annotations

import asyncio
import collections
import hashlib
import hmac
import ipaddress
import logging
import os
import random
import secrets
import socket
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

import config
from . import bencode

LOG = logging.getLogger(__name__)

# Protocol constants, deliberately not configurable.
DHT_NODE_ID_BYTES = 20
DHT_K = 8
COMPACT_IPV4_PEER_BYTES = 6
COMPACT_IPV4_NODE_BYTES = 26
COMPACT_IPV6_NODE_BYTES = 38
MAX_DHT_RESPONSE_BYTES = 1024
DHT_ID_SPACE = 1 << 160


class DHTError(RuntimeError):
    pass


class KRPCError(DHTError):
    def __init__(self, code: int, message: str):
        super().__init__(f"KRPC {code}: {message}")
        self.code = code
        self.message = message


def dht_key_text(key: bytes) -> str:
    if len(key) != DHT_NODE_ID_BYTES:
        raise ValueError("DHT key must be 20 bytes")
    return "dht20:" + key.hex()


def xor_distance(a: bytes, b: bytes) -> int:
    if len(a) != 20 or len(b) != 20:
        raise ValueError("node IDs must be 20 bytes")
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


def compact_peer(endpoint: tuple[str, int]) -> bytes:
    ip, port = endpoint
    addr = ipaddress.ip_address(ip)
    if addr.version != 4 or not (1 <= port <= 65535):
        raise ValueError("compact peer requires IPv4 and valid port")
    return addr.packed + struct.pack("!H", port)


def parse_compact_peer(data: bytes) -> tuple[str, int]:
    if len(data) != COMPACT_IPV4_PEER_BYTES:
        raise ValueError("compact IPv4 peer must be 6 bytes")
    return str(ipaddress.IPv4Address(data[:4])), struct.unpack("!H", data[4:])[0]


def compact_node(node_id: bytes, endpoint: tuple[str, int]) -> bytes:
    if len(node_id) != 20:
        raise ValueError("node ID must be 20 bytes")
    return node_id + compact_peer(endpoint)


def parse_compact_nodes(data: bytes, family: int = 4) -> list[tuple[bytes, str, int]]:
    size = COMPACT_IPV4_NODE_BYTES if family == 4 else COMPACT_IPV6_NODE_BYTES
    if len(data) % size:
        raise ValueError("invalid compact node list length")
    out = []
    for pos in range(0, len(data), size):
        part = data[pos:pos + size]
        node_id = part[:20]
        if family == 4:
            ip = str(ipaddress.IPv4Address(part[20:24]))
            port = struct.unpack("!H", part[24:26])[0]
        else:
            ip = str(ipaddress.IPv6Address(part[20:36]))
            port = struct.unpack("!H", part[36:38])[0]
        out.append((node_id, ip, port))
    return out


def endpoint_allowed(ip: str, port: int, *, local_ips: set[str] | None = None) -> bool:
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:  # active IPv6 DHT explicitly deferred in v0.1
        return False
    if local_ips and str(addr) in local_ips:
        return False
    if config.ALLOW_NON_GLOBAL_ENDPOINTS:
        return not (addr.is_unspecified or addr.is_multicast)
    return addr.is_global


def _safe_text(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")[: config.MAX_EVIDENCE_TEXT_LENGTH]


@dataclass(slots=True)
class Contact:
    node_id: bytes
    ip: str
    port: int
    first_seen_ns: int = field(default_factory=time.monotonic_ns)
    last_response_ns: int | None = None
    last_query_ns: int | None = None
    failures: int = 0
    ever_responded: bool = False
    read_only: bool = False
    client_version: bytes | None = None

    @property
    def endpoint(self) -> tuple[str, int]:
        return self.ip, self.port

    def state(self, now_ns: int | None = None) -> str:
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        if self.failures >= config.DHT_ROUTING_BAD_AFTER_FAILURES:
            return "BAD"
        cutoff = int(config.DHT_ROUTING_GOOD_TTL * 1_000_000_000)
        responsive = self.last_response_ns is not None and now_ns - self.last_response_ns <= cutoff
        queried_us = self.last_query_ns is not None and now_ns - self.last_query_ns <= cutoff
        if responsive or (self.ever_responded and queried_us):
            return "GOOD"
        return "QUESTIONABLE"


@dataclass(slots=True)
class Bucket:
    low: int
    high: int  # exclusive
    contacts: list[Contact] = field(default_factory=list)
    replacements: list[Contact] = field(default_factory=list)
    last_changed_ns: int = field(default_factory=time.monotonic_ns)

    def contains(self, node_id: bytes) -> bool:
        value = int.from_bytes(node_id, "big")
        return self.low <= value < self.high


class RoutingTable:
    def __init__(self, local_node_id: bytes, event: Callable[[dict[str, Any]], None] | None = None):
        if len(local_node_id) != 20:
            raise ValueError("local node ID must be 20 bytes")
        self.local_node_id = local_node_id
        self.buckets = [Bucket(0, DHT_ID_SPACE)]
        self.event = event or (lambda _: None)

    def _bucket_for(self, node_id: bytes) -> Bucket:
        value = int.from_bytes(node_id, "big")
        for bucket in self.buckets:
            if bucket.low <= value < bucket.high:
                return bucket
        raise AssertionError("routing bucket coverage invariant broken")

    def _emit(self, event: str, contact: Contact | None, bucket: Bucket, previous: str | None = None) -> None:
        record: dict[str, Any] = {
            "record_type": "routing",
            "event": event,
            "local_node_id": self.local_node_id.hex(),
            "bucket_min_hex": f"{bucket.low:040x}",
            "bucket_max_hex": f"{bucket.high - 1:040x}",
            "bucket_last_changed_ns": bucket.last_changed_ns,
        }
        if contact is not None:
            record.update({
                "node_id": contact.node_id.hex(), "address_family": "ipv4", "ip": contact.ip,
                "udp_port": contact.port, "routing_state": contact.state(), "previous_routing_state": previous,
            })
        self.event(record)

    def _split(self, bucket: Bucket) -> None:
        midpoint = (bucket.low + bucket.high) // 2
        left, right = Bucket(bucket.low, midpoint), Bucket(midpoint, bucket.high)
        for contact in bucket.contacts:
            (left if left.contains(contact.node_id) else right).contacts.append(contact)
        for contact in bucket.replacements:
            target = left if left.contains(contact.node_id) else right
            if len(target.replacements) < DHT_K:
                target.replacements.append(contact)
        idx = self.buckets.index(bucket)
        self.buckets[idx:idx + 1] = [left, right]
        self._emit("bucket_split", None, left)

    def find(self, node_id: bytes) -> Contact | None:
        for contact in self._bucket_for(node_id).contacts:
            if contact.node_id == node_id:
                return contact
        return None

    def observe(self, node_id: bytes, ip: str, port: int, *, direct_response: bool = False,
                incoming_query: bool = False, read_only: bool = False, client_version: bytes | None = None) -> Contact | None:
        if len(node_id) != 20 or node_id == self.local_node_id:
            return None
        bucket = self._bucket_for(node_id)
        for contact in bucket.contacts:
            if contact.node_id == node_id:
                previous = contact.state()
                # A node ID moving endpoint is treated conservatively until directly responsive.
                if direct_response or (contact.ip == ip and contact.port == port):
                    contact.ip, contact.port = ip, port
                if direct_response:
                    contact.last_response_ns = time.monotonic_ns()
                    contact.ever_responded = True
                    contact.failures = 0
                if incoming_query:
                    contact.last_query_ns = time.monotonic_ns()
                contact.read_only = read_only
                contact.client_version = client_version or contact.client_version
                if contact.state() != previous:
                    self._emit("node_validated" if contact.state() == "GOOD" else "node_questionable", contact, bucket, previous)
                return contact

        candidate = Contact(node_id, ip, port, read_only=read_only, client_version=client_version)
        if direct_response:
            candidate.last_response_ns = time.monotonic_ns()
            candidate.ever_responded = True
        if incoming_query:
            candidate.last_query_ns = time.monotonic_ns()
        self._emit("node_candidate", candidate, bucket)
        if read_only:
            return candidate

        while len(bucket.contacts) >= DHT_K and bucket.contains(self.local_node_id):
            self._split(bucket)
            bucket = self._bucket_for(node_id)
        if len(bucket.contacts) < DHT_K:
            # Indirect contacts may be retained as QUESTIONABLE candidates, never treated as GOOD.
            bucket.contacts.append(candidate)
            bucket.last_changed_ns = time.monotonic_ns()
            self._emit("node_added", candidate, bucket)
            return candidate
        bad = next((c for c in bucket.contacts if c.state() == "BAD"), None)
        if bad is not None:
            bucket.contacts.remove(bad)
            bucket.contacts.append(candidate)
            bucket.last_changed_ns = time.monotonic_ns()
            self._emit("node_removed", bad, bucket)
            self._emit("node_added", candidate, bucket)
            return candidate
        if all(c.node_id != node_id for c in bucket.replacements):
            if len(bucket.replacements) >= DHT_K:
                bucket.replacements.pop(0)
            bucket.replacements.append(candidate)
        return candidate

    def mark_failure(self, node_id: bytes) -> None:
        contact = self.find(node_id)
        if contact is None:
            return
        bucket = self._bucket_for(node_id)
        previous = contact.state()
        contact.failures += 1
        current = contact.state()
        if current != previous:
            self._emit("node_bad" if current == "BAD" else "node_questionable", contact, bucket, previous)
        if current == "BAD" and bucket.replacements:
            replacement = bucket.replacements.pop()
            bucket.contacts.remove(contact)
            bucket.contacts.append(replacement)
            bucket.last_changed_ns = time.monotonic_ns()
            self._emit("node_removed", contact, bucket)
            self._emit("node_added", replacement, bucket)

    def closest(self, target: bytes, limit: int = DHT_K, *, good_only: bool = True) -> list[Contact]:
        contacts = [c for b in self.buckets for c in b.contacts if not c.read_only]
        if good_only:
            contacts = [c for c in contacts if c.state() == "GOOD"]
        contacts.sort(key=lambda c: xor_distance(c.node_id, target))
        return contacts[:limit]

    def all_contacts(self) -> list[Contact]:
        return [c for b in self.buckets for c in b.contacts]

    def snapshot_records(self) -> list[dict[str, Any]]:
        generated = time.time_ns()
        records = [{
            "schema_version": 1, "record_type": "routing_snapshot", "event": "header",
            "local_node_id": self.local_node_id.hex(), "generated_timestamp_ns": generated,
        }]
        for contact in self.all_contacts():
            records.append({
                "schema_version": 1, "record_type": "routing_snapshot", "event": "contact",
                "node_id": contact.node_id.hex(), "address_family": "ipv4", "ip": contact.ip,
                "udp_port": contact.port, "routing_state": contact.state(), "generated_timestamp_ns": generated,
            })
        return records

    def restore_contacts(self, records: Iterable[dict[str, Any]]) -> None:
        for record in records:
            if record.get("event") != "contact":
                continue
            try:
                node_id = bytes.fromhex(record["node_id"])
                ip, port = str(record["ip"]), int(record["udp_port"])
            except (KeyError, TypeError, ValueError):
                continue
            # Restore as unverified/questionable, irrespective of saved state.
            self.observe(node_id, ip, port, direct_response=False)


class TokenManager:
    def __init__(self, clock_ns: Callable[[], int] = time.monotonic_ns):
        self.clock_ns = clock_ns
        now = clock_ns()
        self.current = secrets.token_bytes(32)
        self.previous = secrets.token_bytes(32)
        self.current_created_ns = now
        self.previous_created_ns = now
        self.rotated_ns = now

    def _rotate_if_due(self) -> None:
        now = self.clock_ns()
        interval_ns = int(config.DHT_TOKEN_ROTATION_INTERVAL * 1e9)
        elapsed = now - self.rotated_ns
        if elapsed < interval_ns:
            return
        rotations = max(1, elapsed // interval_ns)
        if rotations == 1:
            self.previous = self.current
            self.previous_created_ns = self.current_created_ns
        else:
            # After two or more missed rotations no formerly-issued token may remain valid.
            self.previous = secrets.token_bytes(32)
            self.previous_created_ns = now
        self.current = secrets.token_bytes(32)
        self.current_created_ns = now
        self.rotated_ns = now

    @staticmethod
    def _derive(secret: bytes, ip: str) -> bytes:
        packed = ipaddress.ip_address(ip).packed
        return hashlib.sha1(packed + secret).digest()[:8]

    def issue(self, ip: str) -> bytes:
        self._rotate_if_due()
        return self._derive(self.current, ip)

    def validate(self, ip: str, token: bytes) -> bool:
        self._rotate_if_due()
        now = self.clock_ns()
        validity_ns = int(config.DHT_TOKEN_VALIDITY * 1e9)
        if now - self.current_created_ns <= validity_ns and hmac.compare_digest(token, self._derive(self.current, ip)):
            return True
        return now - self.previous_created_ns <= validity_ns and hmac.compare_digest(token, self._derive(self.previous, ip))


class PeerStore:
    def __init__(self):
        self._store: collections.OrderedDict[bytes, collections.OrderedDict[tuple[str, int], int]] = collections.OrderedDict()

    def _prune(self, now_ns: int | None = None) -> None:
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        cutoff = now_ns - int(config.DHT_PEER_STORE_TTL * 1e9)
        dead_hashes = []
        for key, peers in self._store.items():
            for endpoint, seen in list(peers.items()):
                if seen < cutoff:
                    peers.pop(endpoint, None)
            if not peers:
                dead_hashes.append(key)
        for key in dead_hashes:
            self._store.pop(key, None)

    def add(self, key: bytes, endpoint: tuple[str, int]) -> None:
        self._prune()
        peers = self._store.get(key)
        if peers is None:
            if len(self._store) >= config.DHT_PEER_STORE_MAX_INFOHASHES:
                self._store.popitem(last=False)
            peers = collections.OrderedDict()
            self._store[key] = peers
        else:
            self._store.move_to_end(key)
        peers[endpoint] = time.monotonic_ns()
        peers.move_to_end(endpoint)
        while len(peers) > config.DHT_PEER_STORE_MAX_PEERS_PER_HASH:
            peers.popitem(last=False)

    def get(self, key: bytes) -> list[tuple[str, int]]:
        self._prune()
        peers = self._store.get(key)
        return list(peers.keys()) if peers else []

    def keys(self) -> list[bytes]:
        self._prune()
        return list(self._store.keys())


@dataclass(slots=True)
class CandidateState:
    dht_key: bytes
    sources: set[str] = field(default_factory=set)
    peer_hints: list[tuple[str, int, bool]] = field(default_factory=list)  # ip, port, implied_port
    queued: bool = True
    first_seen_wall_ns: int = field(default_factory=time.time_ns)
    last_seen_wall_ns: int = field(default_factory=time.time_ns)


class CandidateManager:
    """Bounded in-memory merge/dedupe state feeding the fixed torrent queue."""

    def __init__(self, q: asyncio.Queue[bytes]):
        self.queue = q
        self.states: dict[bytes, CandidateState] = {}
        self.recent: collections.OrderedDict[bytes, int] = collections.OrderedDict()

    def _prune_recent(self) -> None:
        cutoff = time.monotonic_ns() - int(config.RECENT_HASH_TTL * 1e9)
        while self.recent:
            key, ts = next(iter(self.recent.items()))
            if ts >= cutoff and len(self.recent) <= config.RECENT_HASH_CACHE_SIZE:
                break
            self.recent.pop(key, None)

    def submit(self, key: bytes, source: str, peer_hint: tuple[str, int, bool] | None = None, *, retry: bool = False) -> bool:
        if len(key) != 20:
            return False
        self._prune_recent()
        state = self.states.get(key)
        if state is not None:
            state.sources.add(source)
            state.last_seen_wall_ns = time.time_ns()
            if peer_hint and peer_hint not in state.peer_hints and len(state.peer_hints) < config.MAX_PEER_HINTS_PER_CANDIDATE:
                state.peer_hints.append(peer_hint)
            return True
        if not retry and key in self.recent:
            return False
        now_wall = time.time_ns()
        state = CandidateState(key, {source}, [], True, now_wall, now_wall)
        if peer_hint:
            state.peer_hints.append(peer_hint)
        self.states[key] = state  # reserve before enqueue
        try:
            self.queue.put_nowait(key)
        except asyncio.QueueFull:
            self.states.pop(key, None)  # required rollback
            return False
        return True

    def state_for(self, key: bytes) -> CandidateState | None:
        return self.states.get(key)

    def finish(self, key: bytes, *, recent: bool = True) -> None:
        self.states.pop(key, None)
        if recent:
            self.recent[key] = time.monotonic_ns()
            self.recent.move_to_end(key)
            self._prune_recent()


class TokenBucket:
    """Global token bucket with the architecture's three DHT scheduling priorities."""
    def __init__(self, rate: float, burst: int):
        self.rate = float(rate)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()
        self._waiters = [0, 0, 0]  # routing/maintenance, torrent lookup, BEP-51

    async def acquire(self, priority: int = 1) -> None:
        priority = max(0, min(priority, 2))
        self._waiters[priority] += 1
        try:
            while True:
                async with self._lock:
                    now = time.monotonic()
                    self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                    self.updated = now
                    higher_waiting = any(self._waiters[p] > 0 for p in range(priority))
                    if self.tokens >= 1.0 and not higher_waiting:
                        self.tokens -= 1.0
                        return
                    delay = max(0.001, (1.0 - self.tokens) / self.rate) if self.tokens < 1.0 else 0.001
                await asyncio.sleep(min(delay, 0.05))
        finally:
            self._waiters[priority] -= 1


@dataclass(slots=True)
class PendingQuery:
    transaction_id: bytes
    query: bytes
    endpoint: tuple[str, int]
    expected_node_id: bytes | None
    exchange_id: str
    sent_ns: int
    future: asyncio.Future


class DHTProtocol(asyncio.DatagramProtocol):
    def __init__(self, node: "DHTNode"):
        self.node = node

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.node.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) > config.DHT_RECEIVE_MAX_BYTES:
            self.node.emit_error("local", "oversized_datagram", addr, detail=str(len(data)))
            return
        self.node.handle_datagram(data, (str(addr[0]), int(addr[1])))

    def error_received(self, exc: Exception) -> None:
        self.node.emit_error("local", "udp_error", None, detail=str(exc))


class DHTNode:
    def __init__(self, node_id: bytes, candidate_manager: CandidateManager, emit: Callable[[dict[str, Any]], bool]):
        if len(node_id) != 20:
            raise ValueError("node ID must be 20 bytes")
        self.node_id = node_id
        self.client_version = config.DHT_CLIENT_VERSION.encode("ascii")
        self.candidates = candidate_manager
        self.emit = emit
        self.transport: asyncio.DatagramTransport | None = None
        self.routing = RoutingTable(node_id, self._routing_event)
        self.tokens = TokenManager()
        self.peer_store = PeerStore()
        self.rate = TokenBucket(config.DHT_MAX_REQUESTS_PER_SECOND, config.DHT_QUERY_BURST)
        self.pending_slots = asyncio.Semaphore(config.DHT_MAX_PENDING_REQUESTS)
        self.pending: dict[bytes, PendingQuery] = {}
        self._tx_counter = secrets.randbelow(65536)
        self.local_ips = _discover_local_ipv4()
        self._sample_cache: tuple[int, list[bytes]] | None = None
        self._bep51_state: collections.OrderedDict[tuple[str, int], tuple[int, int]] = collections.OrderedDict()
        self._closing = False
        self._last_bootstrap_ns = 0
        self._bootstrap_endpoints: list[tuple[str, int]] = []

    def _routing_event(self, record: dict[str, Any]) -> None:
        self.emit(record)

    def _next_tid(self) -> bytes:
        for _ in range(65536):
            self._tx_counter = (self._tx_counter + 1) & 0xFFFF
            tid = struct.pack("!H", self._tx_counter)
            if tid not in self.pending:
                return tid
        raise DHTError("transaction ID space exhausted")

    def _base(self, tid: bytes, y: bytes) -> dict[bytes, Any]:
        return {b"t": tid, b"y": y, b"v": self.client_version}

    def _send(self, message: dict[bytes, Any], endpoint: tuple[str, int]) -> None:
        if self.transport is None:
            raise DHTError("UDP transport not ready")
        payload = bencode.encode(message)
        if len(payload) > MAX_DHT_RESPONSE_BYTES:
            raise DHTError("outbound DHT datagram exceeds 1024-byte protocol limit")
        self.transport.sendto(payload, endpoint)

    def emit_error(self, source: str, event: str, endpoint: tuple[str, int] | None, *, detail: str = "", exchange_id: str | None = None) -> None:
        record = {"record_type": "error", "event": event, "error_source": source, "exchange_id": exchange_id,
                  "detail": detail[: config.MAX_EVIDENCE_TEXT_LENGTH], **self._local_fields()}
        if endpoint:
            record.update({"remote_ip": endpoint[0], "remote_udp_port": endpoint[1]})
        self.emit(record)

    async def query(self, endpoint: tuple[str, int], method: bytes, args: dict[bytes, Any], *, expected_node_id: bytes | None = None) -> dict[bytes, Any]:
        if self._closing:
            raise DHTError("DHT shutting down")
        if not endpoint_allowed(endpoint[0], endpoint[1], local_ips=self.local_ips):
            raise DHTError("endpoint policy rejected active DHT endpoint")
        priority = 2 if method == b"sample_infohashes" else (1 if method == b"get_peers" else 0)
        await self.rate.acquire(priority)
        await self.pending_slots.acquire()
        loop = asyncio.get_running_loop()
        tid = self._next_tid()
        exchange_id = str(uuid.uuid4())
        future = loop.create_future()
        message = self._base(tid, b"q")
        message[b"q"] = method
        message[b"a"] = {b"id": self.node_id, **args}
        if config.DHT_READ_ONLY:
            message[b"ro"] = 1
        pending = PendingQuery(tid, method, endpoint, expected_node_id, exchange_id, time.monotonic_ns(), future)
        self.pending[tid] = pending
        if config.DEBUG_FULL_KRPC_JSONL or method in {b"get_peers", b"sample_infohashes"}:
            self._emit_query_evidence(message, endpoint, exchange_id, "out", expected_node_id)
        try:
            self._send(message, endpoint)
            response = await asyncio.wait_for(future, timeout=config.DHT_QUERY_TIMEOUT)
            return response
        except asyncio.TimeoutError:
            if expected_node_id:
                self.routing.mark_failure(expected_node_id)
            self.emit_error("local", "krpc_timeout", endpoint, detail=method.decode("ascii", "replace"), exchange_id=exchange_id)
            raise
        finally:
            self.pending.pop(tid, None)
            self.pending_slots.release()

    def handle_datagram(self, data: bytes, endpoint: tuple[str, int]) -> None:
        try:
            msg = bencode.decode(data, max_depth=config.MAX_BENCODE_DEPTH, max_items=config.MAX_BENCODE_ITEMS,
                                  max_string_length=min(config.MAX_BENCODE_STRING_LENGTH, config.DHT_RECEIVE_MAX_BYTES))
            if not isinstance(msg, dict):
                raise bencode.BencodeError("KRPC top-level value is not a dictionary")
            tid = msg.get(b"t")
            y = msg.get(b"y")
            if not isinstance(tid, bytes) or not tid or y not in {b"q", b"r", b"e"}:
                raise bencode.BencodeError("invalid KRPC envelope")
        except (bencode.BencodeError, TypeError, ValueError) as exc:
            self.emit_error("krpc", "malformed_krpc", endpoint, detail=str(exc))
            return
        if y == b"q":
            if config.DHT_READ_ONLY:
                return  # BEP-43: read-only nodes do not respond to queries.
            self._handle_query(msg, endpoint)
        else:
            self._handle_response_or_error(msg, endpoint)

    def _client_fields(self, msg: dict[bytes, Any]) -> dict[str, Any]:
        raw = msg.get(b"v")
        if not isinstance(raw, bytes):
            return {}
        return {"client_version_hex": raw.hex(), "client_version_text": _safe_text(raw)}

    def _local_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {"local_node_id": self.node_id.hex(), "transport_family": "ipv4"}
        if self.transport is not None and hasattr(self.transport, "get_extra_info"):
            try:
                local = self.transport.get_extra_info("sockname")
            except Exception:
                local = None
            if local:
                fields.update({"local_ip": str(local[0]), "local_udp_port": int(local[1])})
        return fields

    def _emit_query_evidence(self, msg: dict[bytes, Any], endpoint: tuple[str, int], exchange_id: str, direction: str,
                             expected_node_id: bytes | None = None) -> None:
        args = msg.get(b"a") if isinstance(msg.get(b"a"), dict) else {}
        method = msg.get(b"q")
        node_id = args.get(b"id") if isinstance(args, dict) else None
        record = {
            "record_type": "krpc", "event": "query", "direction": direction, "exchange_id": exchange_id,
            "transaction_id_hex": msg.get(b"t", b"").hex(), "krpc_message_type": "q",
            "krpc_query": _safe_text(method) if isinstance(method, bytes) else None,
            "remote_ip": endpoint[0], "remote_udp_port": endpoint[1],
            "remote_node_id": ((node_id.hex() if isinstance(node_id, bytes) and len(node_id) == 20 else None)
                               if direction == "in" else (expected_node_id.hex() if isinstance(expected_node_id, bytes) and len(expected_node_id) == 20 else None)),
            "ro": bool(msg.get(b"ro", 0)), **self._local_fields(), **self._client_fields(msg), **_bep42_fields(msg),
        }
        if isinstance(args, dict):
            key = args.get(b"info_hash")
            if isinstance(key, bytes) and len(key) == 20:
                record.update({"wire_info_hash_hex": key.hex(), "dht_key": dht_key_text(key), "want": _decode_want(args.get(b"want"))})
            target = args.get(b"target")
            if isinstance(target, bytes) and len(target) == 20:
                record["target_hex"] = target.hex()
                record["want"] = _decode_want(args.get(b"want"))
        self.emit(record)

    def _handle_query(self, msg: dict[bytes, Any], endpoint: tuple[str, int]) -> None:
        tid = msg[b"t"]
        method = msg.get(b"q")
        args = msg.get(b"a")
        exchange_id = str(uuid.uuid4())
        if not isinstance(method, bytes) or not isinstance(args, dict):
            self._send_error(tid, 203, "Protocol Error", endpoint, exchange_id)
            return
        remote_id = args.get(b"id")
        if not isinstance(remote_id, bytes) or len(remote_id) != 20:
            self._send_error(tid, 203, "Invalid node ID", endpoint, exchange_id)
            return
        ro = bool(msg.get(b"ro", 0))
        # Observe non-global endpoints in JSONL, but never actively route them by default.
        if endpoint_allowed(endpoint[0], endpoint[1], local_ips=self.local_ips):
            self.routing.observe(remote_id, endpoint[0], endpoint[1], incoming_query=True, read_only=ro, client_version=msg.get(b"v") if isinstance(msg.get(b"v"), bytes) else None)
        if config.DEBUG_FULL_KRPC_JSONL or method in {b"get_peers", b"announce_peer", b"sample_infohashes", b"get", b"put"}:
            self._emit_query_evidence(msg, endpoint, exchange_id, "in")
        try:
            if method == b"ping":
                response = {b"id": self.node_id}
            elif method == b"find_node":
                target = _require_20(args, b"target")
                response = {b"id": self.node_id, b"nodes": self._compact_closest(target)}
            elif method == b"get_peers":
                response = self._incoming_get_peers(args, endpoint, exchange_id)
            elif method == b"announce_peer":
                response = self._incoming_announce_peer(args, endpoint, msg, exchange_id)
            elif method == b"sample_infohashes" and config.DHT_BEP51_ENABLED:
                response = self._incoming_sample_infohashes(args, exchange_id)
            elif method in {b"get", b"put"}:
                self._emit_bep44_observation(method, args, endpoint, exchange_id)
                self._send_error(tid, 204, "Method Unknown", endpoint, exchange_id, associated_query=method)
                return
            else:
                self._send_error(tid, 204, "Method Unknown", endpoint, exchange_id, associated_query=method)
                return
            message = self._base(tid, b"r")
            message[b"r"] = response
            if len(bencode.encode(message)) > MAX_DHT_RESPONSE_BYTES:
                raise KRPCError(202, "Response too large")
            self._send(message, endpoint)
            if config.DEBUG_FULL_KRPC_JSONL or method in {b"get_peers", b"announce_peer", b"sample_infohashes"}:
                self._emit_response_evidence(message, endpoint, exchange_id, method, "out", time.monotonic_ns())
        except (ValueError, TypeError) as exc:
            self._send_error(tid, 203, str(exc), endpoint, exchange_id, associated_query=method)
        except KRPCError as exc:
            self._send_error(tid, exc.code, exc.message, endpoint, exchange_id, associated_query=method)

    def _send_error(self, tid: bytes, code: int, text: str, endpoint: tuple[str, int], exchange_id: str, associated_query: bytes | None = None) -> None:
        message = self._base(tid, b"e")
        message[b"e"] = [code, text.encode("utf-8")[: config.MAX_EVIDENCE_TEXT_LENGTH]]
        try:
            self._send(message, endpoint)
        except DHTError:
            pass
        self.emit({
            "record_type": "error", "event": "krpc_error", "error_source": "krpc", "exchange_id": exchange_id,
            "transaction_id_hex": tid.hex(), "associated_query": _safe_text(associated_query),
            "krpc_error_code": code, "krpc_error_message": text[: config.MAX_EVIDENCE_TEXT_LENGTH], "remote_ip": endpoint[0], "remote_udp_port": endpoint[1],
            **self._local_fields(),
        })

    def _handle_response_or_error(self, msg: dict[bytes, Any], endpoint: tuple[str, int]) -> None:
        tid = msg[b"t"]
        pending = self.pending.get(tid)
        if pending is None:
            return
        # Transaction ID AND source endpoint AND query state are required.
        if endpoint != pending.endpoint:
            self.emit_error("krpc", "response_endpoint_mismatch", endpoint, exchange_id=pending.exchange_id)
            return
        if msg[b"y"] == b"e":
            error = msg.get(b"e")
            if isinstance(error, list) and len(error) >= 2 and isinstance(error[0], int):
                exc = KRPCError(error[0], _safe_text(error[1]) if isinstance(error[1], bytes) else "remote error")
            else:
                exc = KRPCError(201, "Malformed remote error")
            if not pending.future.done():
                pending.future.set_exception(exc)
            self.emit({
                "record_type": "error", "event": "krpc_error", "error_source": "krpc", "exchange_id": pending.exchange_id,
                "transaction_id_hex": tid.hex(), "associated_query": _safe_text(pending.query), "krpc_error_code": exc.code,
                "krpc_error_message": exc.message, "remote_ip": endpoint[0], "remote_udp_port": endpoint[1],
            })
            return
        response = msg.get(b"r")
        if not isinstance(response, dict):
            self.emit_error("krpc", "malformed_response", endpoint, exchange_id=pending.exchange_id)
            return
        remote_id = response.get(b"id")
        if not isinstance(remote_id, bytes) or len(remote_id) != 20:
            self.emit_error("krpc", "response_missing_node_id", endpoint, exchange_id=pending.exchange_id)
            return
        if pending.expected_node_id is not None and remote_id != pending.expected_node_id:
            self.emit_error("krpc", "response_node_id_mismatch", endpoint, exchange_id=pending.exchange_id)
            return
        if not _response_matches_query(pending.query, response):
            self.emit_error("krpc", "response_query_state_mismatch", endpoint, exchange_id=pending.exchange_id)
            return
        if endpoint_allowed(endpoint[0], endpoint[1], local_ips=self.local_ips):
            self.routing.observe(remote_id, endpoint[0], endpoint[1], direct_response=True, client_version=msg.get(b"v") if isinstance(msg.get(b"v"), bytes) else None)
        important = config.DEBUG_FULL_KRPC_JSONL or pending.query in {b"get_peers", b"sample_infohashes"}
        self._parse_response_contacts(response, pending.exchange_id, emit_children=important)
        if important:
            self._emit_response_evidence(msg, endpoint, pending.exchange_id, pending.query, "in", pending.sent_ns)
        if not pending.future.done():
            pending.future.set_result(response)

    def _parse_response_contacts(self, response: dict[bytes, Any], exchange_id: str, *, emit_children: bool = True) -> None:
        for key, family in ((b"nodes", 4), (b"nodes6", 6)):
            raw = response.get(key)
            if not isinstance(raw, bytes):
                continue
            try:
                contacts = parse_compact_nodes(raw, family)
            except ValueError:
                continue
            for idx, (node_id, ip, port) in enumerate(contacts):
                if emit_children:
                    self.emit({
                        "record_type": "node", "event": "returned_node", "exchange_id": exchange_id, "contact_index": idx,
                        "node_id": node_id.hex(), "address_family": "ipv4" if family == 4 else "ipv6", "ip": ip, "udp_port": port,
                    })
                if family == 4 and endpoint_allowed(ip, port, local_ips=self.local_ips):
                    self.routing.observe(node_id, ip, port, direct_response=False)

    def _emit_response_evidence(self, msg: dict[bytes, Any], endpoint: tuple[str, int], exchange_id: str,
                                query: bytes, direction: str, sent_ns: int) -> None:
        response = msg.get(b"r") if isinstance(msg.get(b"r"), dict) else {}
        now = time.monotonic_ns()
        token = response.get(b"token") if isinstance(response, dict) else None
        record = {
            "record_type": "krpc", "event": "response", "direction": direction, "exchange_id": exchange_id,
            "transaction_id_hex": msg.get(b"t", b"").hex(), "krpc_message_type": "r", "krpc_query": _safe_text(query),
            "remote_ip": endpoint[0], "remote_udp_port": endpoint[1],
            "remote_node_id": (response.get(b"id").hex() if direction == "in" and isinstance(response.get(b"id"), bytes) and len(response.get(b"id")) == 20 else None),
            "response_ms": max(0.0, (now - sent_ns) / 1e6), "token_present": isinstance(token, bytes),
            "token_length": len(token) if isinstance(token, bytes) else None,
            "token_sha256": hashlib.sha256(token).hexdigest() if isinstance(token, bytes) else None,
            **self._local_fields(), **self._client_fields(msg), **_bep42_fields(msg),
        }
        if isinstance(response, dict):
            values = response.get(b"values")
            record["returned_peer_count"] = len(values) if isinstance(values, list) else 0
            raw_nodes = response.get(b"nodes")
            record["returned_node4_count"] = len(raw_nodes) // 26 if isinstance(raw_nodes, bytes) and len(raw_nodes) % 26 == 0 else 0
            raw_nodes6 = response.get(b"nodes6")
            record["returned_node6_count"] = len(raw_nodes6) // 38 if isinstance(raw_nodes6, bytes) and len(raw_nodes6) % 38 == 0 else 0
            if query == b"sample_infohashes":
                samples = response.get(b"samples")
                record.update({"interval": response.get(b"interval"), "num": response.get(b"num"),
                               "returned_sample_count": len(samples) // 20 if isinstance(samples, bytes) and len(samples) % 20 == 0 else 0})
                if isinstance(samples, bytes) and len(samples) % 20 == 0:
                    for idx in range(0, len(samples), 20):
                        key = samples[idx:idx + 20]
                        self.emit({"record_type": "discovery", "event": "bep51_sample", "exchange_id": exchange_id,
                                   "sample_index": idx // 20, "wire_dht_key_hex": key.hex(), "dht_key": dht_key_text(key)})
                        self.candidates.submit(key, "bep51")
            if isinstance(values, list):
                for idx, raw in enumerate(values):
                    if not isinstance(raw, bytes):
                        continue
                    try:
                        ip, port = parse_compact_peer(raw)
                    except ValueError:
                        continue
                    self.emit({"record_type": "peer", "event": "get_peers_value", "exchange_id": exchange_id,
                               "contact_index": idx, "address_family": "ipv4", "ip": ip, "port": port})
        self.emit(record)

    def _compact_closest(self, target: bytes) -> bytes:
        return b"".join(compact_node(c.node_id, c.endpoint) for c in self.routing.closest(target, DHT_K, good_only=True))

    def _incoming_get_peers(self, args: dict[bytes, Any], endpoint: tuple[str, int], exchange_id: str) -> dict[bytes, Any]:
        key = _require_20(args, b"info_hash")
        _validate_want(args.get(b"want"))
        self.candidates.submit(key, "get_peers")
        self.emit({"record_type": "discovery", "event": "passive_get_peers", "exchange_id": exchange_id,
                   "wire_info_hash_hex": key.hex(), "dht_key": dht_key_text(key)})
        response: dict[bytes, Any] = {b"id": self.node_id, b"token": self.tokens.issue(endpoint[0])}
        peers = self.peer_store.get(key)
        if peers:
            values: list[bytes] = []
            for peer in peers:
                if not endpoint_allowed(peer[0], peer[1], local_ips=self.local_ips):
                    continue
                candidate = values + [compact_peer(peer)]
                trial = self._base(b"aa", b"r") | {b"r": response | {b"values": candidate}}
                if len(bencode.encode(trial)) > MAX_DHT_RESPONSE_BYTES:
                    break
                values = candidate
            response[b"values"] = values
        else:
            nodes = b""
            for contact in self.routing.closest(key, DHT_K, good_only=True):
                candidate = nodes + compact_node(contact.node_id, contact.endpoint)
                trial = self._base(b"aa", b"r") | {b"r": response | {b"nodes": candidate}}
                if len(bencode.encode(trial)) > MAX_DHT_RESPONSE_BYTES:
                    break
                nodes = candidate
            response[b"nodes"] = nodes
        return response

    def _incoming_announce_peer(self, args: dict[bytes, Any], endpoint: tuple[str, int], msg: dict[bytes, Any], exchange_id: str) -> dict[bytes, Any]:
        key = _require_20(args, b"info_hash")
        token = args.get(b"token")
        port_arg = args.get(b"port")
        implied = args.get(b"implied_port", 0)
        if not isinstance(port_arg, int) or not (1 <= port_arg <= 65535):
            raise ValueError("invalid announce port")
        if not isinstance(implied, int):
            raise ValueError("invalid implied_port")
        effective_port = endpoint[1] if implied != 0 else port_arg
        token_valid = isinstance(token, bytes) and self.tokens.validate(endpoint[0], token)
        remote_id = args.get(b"id")
        self.emit({
            "record_type": "discovery", "event": "announce_peer", "exchange_id": exchange_id,
            "announcing_node_id": remote_id.hex() if isinstance(remote_id, bytes) else None,
            "source_ip": endpoint[0], "source_udp_port": endpoint[1], "wire_info_hash_hex": key.hex(), "dht_key": dht_key_text(key),
            "announce_port_argument": port_arg, "implied_port": implied != 0, "effective_peer_port": effective_port,
            "token_present": isinstance(token, bytes), "token_length": len(token) if isinstance(token, bytes) else None,
            "token_sha256": hashlib.sha256(token).hexdigest() if isinstance(token, bytes) else None, "token_valid": token_valid,
            "ro": bool(msg.get(b"ro", 0)),
        })
        if not token_valid:
            raise KRPCError(203, "Bad token")
        peer_endpoint = (endpoint[0], effective_port)
        if endpoint_allowed(peer_endpoint[0], peer_endpoint[1], local_ips=self.local_ips):
            self.peer_store.add(key, peer_endpoint)
            self.candidates.submit(key, "announce_peer", (peer_endpoint[0], peer_endpoint[1], implied != 0))
        return {b"id": self.node_id}

    def _incoming_sample_infohashes(self, args: dict[bytes, Any], exchange_id: str) -> dict[bytes, Any]:
        target = _require_20(args, b"target")
        keys = self.peer_store.keys()
        now = time.monotonic_ns()
        interval_ns = int(config.DHT_BEP51_RESPONSE_INTERVAL * 1e9)
        if self._sample_cache is None or now >= self._sample_cache[0]:
            count = min(config.BEP51_MAX_SAMPLES_PER_RESPONSE, len(keys))
            sampled = random.sample(keys, count) if count and count < len(keys) else list(keys[:count])
            self._sample_cache = (now + interval_ns if interval_ns else now, sampled)
        samples = self._sample_cache[1]
        response: dict[bytes, Any] = {
            b"id": self.node_id, b"interval": config.DHT_BEP51_RESPONSE_INTERVAL,
            b"num": len(keys), b"samples": b"".join(samples),
        }
        nodes = b""
        for contact in self.routing.closest(target, DHT_K, good_only=True):
            candidate = nodes + compact_node(contact.node_id, contact.endpoint)
            trial_response = response | {b"nodes": candidate}
            trial = self._base(b"aa", b"r") | {b"r": trial_response}
            if len(bencode.encode(trial)) > MAX_DHT_RESPONSE_BYTES:
                break
            nodes = candidate
        response[b"nodes"] = nodes
        # If sample count itself makes response too large, trim while retaining samples field.
        while len(bencode.encode(self._base(b"aa", b"r") | {b"r": response})) > MAX_DHT_RESPONSE_BYTES and samples:
            samples = samples[:-1]
            response[b"samples"] = b"".join(samples)
        return response

    def _emit_bep44_observation(self, method: bytes, args: dict[bytes, Any], endpoint: tuple[str, int], exchange_id: str) -> None:
        record: dict[str, Any] = {"record_type": "krpc", "event": "bep44_observation", "exchange_id": exchange_id,
                                  "krpc_query": method.decode("ascii"), "remote_ip": endpoint[0], "remote_udp_port": endpoint[1]}
        for key in (b"target", b"k", b"sig", b"salt"):
            value = args.get(key)
            if isinstance(value, bytes):
                record[key.decode("ascii") + "_hex"] = value.hex()
        for key in (b"seq", b"cas"):
            value = args.get(key)
            if isinstance(value, int):
                record[key.decode("ascii")] = value
        value = args.get(b"v")
        if isinstance(value, bytes):
            record["value_length"] = len(value)
            record["value_sha256"] = hashlib.sha256(value).hexdigest()
        token = args.get(b"token")
        if isinstance(token, bytes):
            record.update({"token_present": True, "token_length": len(token), "token_sha256": hashlib.sha256(token).hexdigest()})
        self.emit(record)

    async def ping(self, contact: Contact) -> bool:
        try:
            await self.query(contact.endpoint, b"ping", {}, expected_node_id=contact.node_id)
            return True
        except (DHTError, KRPCError, asyncio.TimeoutError):
            return False

    def resolve_bootstrap_nodes(self) -> None:
        """Resolve configured bootstrap DNS synchronously before UDP ingress starts."""
        endpoints: list[tuple[str, int]] = []
        for host, port in config.DHT_BOOTSTRAP_NODES:
            try:
                infos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
            except socket.gaierror:
                continue
            for info in infos:
                ep = (str(info[4][0]), int(info[4][1]))
                if ep not in endpoints and endpoint_allowed(ep[0], ep[1], local_ips=self.local_ips):
                    endpoints.append(ep)
        self._bootstrap_endpoints = endpoints

    async def bootstrap(self) -> None:
        self._last_bootstrap_ns = time.monotonic_ns()
        for endpoint in self._bootstrap_endpoints:
            try:
                response = await self.query(endpoint, b"find_node", {b"target": self.node_id})
                remote_id = response.get(b"id")
                if isinstance(remote_id, bytes) and len(remote_id) == 20:
                    self.routing.observe(remote_id, endpoint[0], endpoint[1], direct_response=True)
            except (DHTError, KRPCError, asyncio.TimeoutError):
                continue

    async def iterative_get_peers(self, key: bytes) -> list[tuple[str, int]]:
        if len(key) != 20:
            raise ValueError("target key must be 20 bytes")
        deadline = time.monotonic() + config.DHT_LOOKUP_DEADLINE
        shortlist: dict[bytes, Contact] = {c.node_id: c for c in self.routing.closest(key, max(DHT_K, config.DHT_LOOKUP_PARALLELISM), good_only=False)}
        queried: set[bytes] = set()
        peers: list[tuple[str, int]] = []
        query_count = 0
        previous_frontier: tuple[bytes, ...] | None = None
        while time.monotonic() < deadline and query_count < config.MAX_DHT_QUERIES_PER_TORRENT and len(peers) < config.MAX_PEERS_PER_TORRENT:
            ordered = sorted(shortlist.values(), key=lambda c: xor_distance(c.node_id, key))
            frontier = tuple(c.node_id for c in ordered[:DHT_K])
            batch = [c for c in ordered if c.node_id not in queried and endpoint_allowed(c.ip, c.port, local_ips=self.local_ips)][: config.DHT_LOOKUP_PARALLELISM]
            if not batch:
                break
            if previous_frontier == frontier and all(node_id in queried for node_id in frontier):
                break
            previous_frontier = frontier
            tasks = []
            for contact in batch:
                queried.add(contact.node_id)
                query_count += 1
                tasks.append(asyncio.create_task(self.query(contact.endpoint, b"get_peers", {b"info_hash": key}, expected_node_id=contact.node_id)))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    continue
                values = result.get(b"values")
                if isinstance(values, list):
                    for raw in values:
                        if not isinstance(raw, bytes):
                            continue
                        try:
                            endpoint = parse_compact_peer(raw)
                        except ValueError:
                            continue
                        if endpoint_allowed(endpoint[0], endpoint[1], local_ips=self.local_ips) and endpoint not in peers:
                            peers.append(endpoint)
                            if len(peers) >= config.MAX_PEERS_PER_TORRENT:
                                break
                raw_nodes = result.get(b"nodes")
                if isinstance(raw_nodes, bytes):
                    try:
                        nodes = parse_compact_nodes(raw_nodes, 4)
                    except ValueError:
                        nodes = []
                    for node_id, ip, port in nodes:
                        if endpoint_allowed(ip, port, local_ips=self.local_ips):
                            contact = self.routing.observe(node_id, ip, port, direct_response=False)
                            if contact is not None:
                                shortlist[node_id] = contact
        return peers[: config.MAX_PEERS_PER_TORRENT]

    async def maintenance_once(self) -> None:
        # Routing/maintenance gets scheduling priority by being called independently of BEP-51.
        now = time.monotonic_ns()
        if not self.routing.closest(self.node_id, 1, good_only=True) and now - self._last_bootstrap_ns >= int(config.DHT_BOOTSTRAP_RETRY_INTERVAL * 1e9):
            await self.bootstrap()
        questionable = [c for c in self.routing.all_contacts() if c.state() == "QUESTIONABLE"]
        for contact in questionable[:DHT_K]:
            await self.ping(contact)
        now = time.monotonic_ns()
        stale_after = int(config.DHT_ROUTING_REFRESH_INTERVAL * 1e9)
        stale = [b for b in self.routing.buckets if now - b.last_changed_ns >= stale_after]
        if stale:
            bucket = stale[0]
            target_int = random.randrange(bucket.low, bucket.high)
            target = target_int.to_bytes(20, "big")
            starters = self.routing.closest(target, 1, good_only=True)
            if starters:
                try:
                    await self.query(starters[0].endpoint, b"find_node", {b"target": target}, expected_node_id=starters[0].node_id)
                except (DHTError, KRPCError, asyncio.TimeoutError):
                    pass
            bucket.last_changed_ns = now
            self._routing_event({"record_type": "routing", "event": "bucket_refresh", "local_node_id": self.node_id.hex(),
                                 "bucket_min_hex": f"{bucket.low:040x}", "bucket_max_hex": f"{bucket.high - 1:040x}",
                                 "bucket_last_changed_ns": bucket.last_changed_ns})

    async def bep51_once(self, hash_queue: asyncio.Queue[bytes]) -> None:
        if not config.DHT_BEP51_ENABLED:
            return
        utilization = hash_queue.qsize() / max(1, hash_queue.maxsize)
        if utilization >= config.BEP51_QUEUE_HIGH_WATERMARK:
            return
        now_ns = time.monotonic_ns()
        self._prune_bep51_state(now_ns)
        target = os.urandom(20)
        shortlist: dict[bytes, Contact] = {c.node_id: c for c in self.routing.closest(target, DHT_K, good_only=True)}
        visited: set[bytes] = set()
        max_nodes = DHT_K if utilization <= config.BEP51_QUEUE_LOW_WATERMARK else 1
        processed = 0
        while processed < max_nodes:
            ordered = sorted(shortlist.values(), key=lambda c: xor_distance(c.node_id, target))
            contact = next((c for c in ordered if c.node_id not in visited), None)
            if contact is None:
                break
            visited.add(contact.node_id)
            state = self._bep51_state.get(contact.endpoint)
            if state is not None and now_ns < state[0]:
                continue
            try:
                response = await self.query(contact.endpoint, b"sample_infohashes", {b"target": target}, expected_node_id=contact.node_id)
            except KRPCError as exc:
                if exc.code == 204:
                    self._remember_bep51(contact.endpoint, now_ns + int(config.DHT_BEP51_UNSUPPORTED_BACKOFF * 1e9), now_ns)
                continue
            except (DHTError, asyncio.TimeoutError):
                continue
            interval = response.get(b"interval", config.DHT_BEP51_GLOBAL_INTERVAL)
            if not isinstance(interval, int) or not (0 <= interval <= 21600):
                interval = int(config.DHT_BEP51_GLOBAL_INTERVAL)
            self._remember_bep51(contact.endpoint, now_ns + int(max(interval, config.DHT_BEP51_GLOBAL_INTERVAL) * 1e9), now_ns)
            processed += 1
            raw_nodes = response.get(b"nodes")
            if isinstance(raw_nodes, bytes):
                try:
                    returned = parse_compact_nodes(raw_nodes, 4)
                except ValueError:
                    returned = []
                for node_id, ip, port in returned:
                    if endpoint_allowed(ip, port, local_ips=self.local_ips):
                        candidate = self.routing.observe(node_id, ip, port, direct_response=False)
                        if candidate is not None:
                            shortlist[node_id] = candidate

    def _remember_bep51(self, endpoint: tuple[str, int], due_ns: int, seen_ns: int) -> None:
        self._bep51_state[endpoint] = (due_ns, seen_ns)
        self._bep51_state.move_to_end(endpoint)
        while len(self._bep51_state) > config.BEP51_NODE_STATE_MAX:
            self._bep51_state.popitem(last=False)

    def _prune_bep51_state(self, now_ns: int) -> None:
        cutoff = now_ns - int(config.BEP51_NODE_STATE_TTL * 1e9)
        for endpoint, (_, seen) in list(self._bep51_state.items()):
            if seen < cutoff:
                self._bep51_state.pop(endpoint, None)

    def close_ingress(self) -> None:
        self._closing = True
        if self.transport is not None:
            self.transport.close()
            self.transport = None
        for pending in list(self.pending.values()):
            if not pending.future.done():
                pending.future.set_exception(DHTError("DHT shutdown"))


async def bind_udp(node: DHTNode) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: DHTProtocol(node), local_addr=(config.DHT_BIND_HOST, config.DHT_BIND_PORT), family=socket.AF_INET)
    return transport  # type: ignore[return-value]


def _discover_local_ipv4() -> set[str]:
    ips = {"127.0.0.1", "0.0.0.0"}
    if config.DHT_BIND_HOST != "0.0.0.0":
        ips.add(config.DHT_BIND_HOST)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET):
            ips.add(str(info[4][0]))
    except socket.gaierror:
        pass
    return ips


def _bep42_fields(msg: dict[bytes, Any]) -> dict[str, Any]:
    raw = msg.get(b"ip")
    if not isinstance(raw, bytes):
        return {}
    try:
        if len(raw) == 6:
            return {"bep42_observed_ip": str(ipaddress.IPv4Address(raw[:4])), "bep42_observed_port": struct.unpack("!H", raw[4:])[0]}
        if len(raw) == 18:
            return {"bep42_observed_ip": str(ipaddress.IPv6Address(raw[:16])), "bep42_observed_port": struct.unpack("!H", raw[16:])[0]}
    except (ipaddress.AddressValueError, struct.error):
        pass
    return {}


def _response_matches_query(query: bytes, response: dict[bytes, Any]) -> bool:
    if query == b"ping":
        return True
    if query == b"find_node":
        return isinstance(response.get(b"nodes"), bytes) or isinstance(response.get(b"nodes6"), bytes)
    if query == b"get_peers":
        token = response.get(b"token")
        values = response.get(b"values")
        has_nodes = isinstance(response.get(b"nodes"), bytes) or isinstance(response.get(b"nodes6"), bytes)
        return isinstance(token, bytes) and ((isinstance(values, list) and all(isinstance(v, bytes) for v in values)) or has_nodes)
    if query == b"sample_infohashes":
        return (isinstance(response.get(b"interval"), int) and isinstance(response.get(b"num"), int)
                and isinstance(response.get(b"samples"), bytes)
                and (isinstance(response.get(b"nodes"), bytes) or isinstance(response.get(b"nodes6"), bytes)))
    return True


def _require_20(args: dict[bytes, Any], key: bytes) -> bytes:
    value = args.get(key)
    if not isinstance(value, bytes) or len(value) != 20:
        raise ValueError(f"{key.decode('ascii')} must be 20 bytes")
    return value


def _validate_want(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list) or any(not isinstance(item, bytes) for item in value):
        raise ValueError("want must be a list of byte strings")
    # Forward-compatible: unknown wants are ignored rather than rejected.


def _decode_want(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    return [_safe_text(item) or "" for item in value if isinstance(item, bytes)]
