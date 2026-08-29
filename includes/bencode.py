"""Strict, bounded bencode codec used by DHT and BitTorrent metadata."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class BencodeError(ValueError):
    """Raised for malformed or limit-exceeding bencode."""


@dataclass(slots=True)
class DecodeLimits:
    max_depth: int
    max_items: int
    max_string_length: int


class _Decoder:
    def __init__(self, data: bytes, limits: DecodeLimits):
        self.data = data
        self.limits = limits
        self.items = 0

    def _count(self) -> None:
        self.items += 1
        if self.items > self.limits.max_items:
            raise BencodeError("maximum bencode item count exceeded")

    def parse(self, pos: int = 0, depth: int = 0) -> tuple[Any, int]:
        if depth > self.limits.max_depth:
            raise BencodeError("maximum bencode depth exceeded")
        if pos >= len(self.data):
            raise BencodeError("unexpected end of bencode")
        self._count()
        marker = self.data[pos]
        if marker == ord("i"):
            return self._parse_int(pos)
        if marker == ord("l"):
            out: list[Any] = []
            pos += 1
            while True:
                if pos >= len(self.data):
                    raise BencodeError("unterminated list")
                if self.data[pos] == ord("e"):
                    return out, pos + 1
                value, pos = self.parse(pos, depth + 1)
                out.append(value)
        if marker == ord("d"):
            out: dict[bytes, Any] = {}
            pos += 1
            previous: bytes | None = None
            while True:
                if pos >= len(self.data):
                    raise BencodeError("unterminated dictionary")
                if self.data[pos] == ord("e"):
                    return out, pos + 1
                self._count()
                key, pos = self._parse_bytes(pos)
                if previous is not None and key <= previous:
                    raise BencodeError("dictionary keys must be strictly sorted")
                previous = key
                value, pos = self.parse(pos, depth + 1)
                out[key] = value
        if 48 <= marker <= 57:
            return self._parse_bytes(pos)
        raise BencodeError(f"invalid bencode marker at offset {pos}")

    def _parse_int(self, pos: int) -> tuple[int, int]:
        end = self.data.find(b"e", pos + 1)
        if end < 0:
            raise BencodeError("unterminated integer")
        raw = self.data[pos + 1:end]
        if not raw:
            raise BencodeError("empty integer")
        if raw == b"-0" or (raw.startswith(b"0") and len(raw) > 1) or (raw.startswith(b"-0") and len(raw) > 2):
            raise BencodeError("non-canonical integer")
        if raw[0:1] == b"-":
            digits = raw[1:]
            if not digits:
                raise BencodeError("invalid integer")
        else:
            digits = raw
        if not digits.isdigit():
            raise BencodeError("invalid integer digits")
        return int(raw), end + 1

    def _parse_bytes(self, pos: int) -> tuple[bytes, int]:
        colon = self.data.find(b":", pos)
        if colon < 0:
            raise BencodeError("missing byte-string colon")
        raw_len = self.data[pos:colon]
        if not raw_len or not raw_len.isdigit():
            raise BencodeError("invalid byte-string length")
        if len(raw_len) > 1 and raw_len.startswith(b"0"):
            raise BencodeError("non-canonical byte-string length")
        size = int(raw_len)
        if size > self.limits.max_string_length:
            raise BencodeError("maximum bencode string length exceeded")
        start = colon + 1
        end = start + size
        if end > len(self.data):
            raise BencodeError("truncated byte string")
        return self.data[start:end], end


def decode_prefix(data: bytes, *, max_depth: int, max_items: int, max_string_length: int) -> tuple[Any, int]:
    """Decode one bencode value and return ``(value, consumed_bytes)``."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    decoder = _Decoder(bytes(data), DecodeLimits(max_depth, max_items, max_string_length))
    return decoder.parse()


def decode(data: bytes, *, max_depth: int, max_items: int, max_string_length: int) -> Any:
    """Decode exactly one bencode value, rejecting trailing data."""
    value, consumed = decode_prefix(data, max_depth=max_depth, max_items=max_items, max_string_length=max_string_length)
    if consumed != len(data):
        raise BencodeError("trailing data after bencode value")
    return value


def encode(value: Any) -> bytes:
    """Encode a supported Python value using canonical bencode ordering."""
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii") + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode("ascii") + b":" + value
    if isinstance(value, bytearray):
        return encode(bytes(value))
    if isinstance(value, str):
        return encode(value.encode("utf-8"))
    if isinstance(value, (list, tuple)):
        return b"l" + b"".join(encode(item) for item in value) + b"e"
    if isinstance(value, dict):
        pairs: list[tuple[bytes, Any]] = []
        for key, item in value.items():
            if isinstance(key, str):
                key_b = key.encode("utf-8")
            elif isinstance(key, bytes):
                key_b = key
            else:
                raise TypeError("bencode dictionary keys must be str or bytes")
            pairs.append((key_b, item))
        pairs.sort(key=lambda pair: pair[0])
        out = bytearray(b"d")
        previous: bytes | None = None
        for key_b, item in pairs:
            if previous == key_b:
                raise ValueError("duplicate dictionary key after encoding")
            previous = key_b
            out += encode(key_b)
            out += encode(item)
        out += b"e"
        return bytes(out)
    raise TypeError(f"unsupported bencode type: {type(value).__name__}")
