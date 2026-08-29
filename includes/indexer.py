"""Torrent metadata indexing after exact-byte identity validation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import config
from . import bencode


class IndexingError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class IndexedFile:
    index: int
    path: str
    size: int


@dataclass(slots=True, frozen=True)
class IndexedTorrent:
    torrent_uid: str
    name: str | None
    total_size: int
    file_count: int
    piece_length: int | None
    metadata_size: int
    raw_info: bytes
    files: tuple[IndexedFile, ...]


def _text(value: Any) -> str | None:
    if not isinstance(value, bytes):
        return None
    text = value.decode("utf-8", errors="replace")
    if len(text) > config.MAX_INDEX_TEXT_LENGTH:
        text = text[: config.MAX_INDEX_TEXT_LENGTH]
    return text


def _component(value: Any) -> str:
    text = _text(value)
    if text is None:
        raise IndexingError("path component is not a byte string")
    text = text.replace("\\", "/").replace("\x00", "")
    text = text.strip("/")
    if text in {"", ".", ".."}:
        raise IndexingError("unsafe or empty path component")
    return text


def parse_validated_info(raw_info: bytes, torrent_uid: str) -> IndexedTorrent:
    info = bencode.decode(
        raw_info,
        max_depth=config.MAX_BENCODE_DEPTH,
        max_items=config.MAX_BENCODE_ITEMS,
        max_string_length=config.MAX_BENCODE_STRING_LENGTH,
    )
    if not isinstance(info, dict):
        raise IndexingError("info metadata must be a dictionary")

    name = _text(info.get(b"name.utf-8")) or _text(info.get(b"name"))
    piece_length = info.get(b"piece length")
    if piece_length is not None and (not isinstance(piece_length, int) or piece_length <= 0):
        raise IndexingError("invalid piece length")

    files: list[IndexedFile] = []
    if b"files" in info:
        file_entries = info[b"files"]
        if not isinstance(file_entries, list):
            raise IndexingError("files must be a list")
        if len(file_entries) > config.MAX_FILES_PER_TORRENT:
            raise IndexingError("maximum file count exceeded")
        for idx, entry in enumerate(file_entries):
            if not isinstance(entry, dict):
                raise IndexingError("file entry must be a dictionary")
            size = entry.get(b"length")
            if not isinstance(size, int) or size < 0:
                raise IndexingError("invalid file length")
            path_value = entry.get(b"path.utf-8", entry.get(b"path"))
            if not isinstance(path_value, list) or not path_value:
                raise IndexingError("invalid file path")
            if len(path_value) > config.MAX_PATH_COMPONENTS:
                raise IndexingError("maximum path components exceeded")
            path = "/".join(_component(part) for part in path_value)
            files.append(IndexedFile(idx, path, size))
    else:
        size = info.get(b"length")
        if not isinstance(size, int) or size < 0:
            raise IndexingError("single-file torrent requires non-negative length")
        files.append(IndexedFile(0, name or "unnamed", size))

    total_size = sum(item.size for item in files)
    return IndexedTorrent(
        torrent_uid=torrent_uid,
        name=name,
        total_size=total_size,
        file_count=len(files),
        piece_length=piece_length,
        metadata_size=len(raw_info),
        raw_info=raw_info,
        files=tuple(files),
    )
