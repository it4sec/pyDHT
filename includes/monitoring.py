"""Keyword matching over confirmed torrent metadata."""
from __future__ import annotations

from dataclasses import dataclass
from .indexer import IndexedTorrent


@dataclass(slots=True, frozen=True)
class KeywordResult:
    keywords: tuple[str, ...]
    matches: tuple[str, ...]


def match_keywords(torrent: IndexedTorrent, keywords: tuple[str, ...], *, case_sensitive: bool = False) -> KeywordResult | None:
    if not keywords:
        return None
    values = []
    if torrent.name:
        values.append(torrent.name)
    values.extend(file.path for file in torrent.files)
    matched_keywords: list[str] = []
    matched_values: list[str] = []
    for keyword in keywords:
        if not keyword:
            continue
        needle = keyword if case_sensitive else keyword.casefold()
        found = False
        for value in values:
            haystack = value if case_sensitive else value.casefold()
            if needle in haystack:
                found = True
                if value not in matched_values:
                    matched_values.append(value)
        if found:
            matched_keywords.append(keyword)
    if not matched_keywords:
        return None
    return KeywordResult(tuple(matched_keywords), tuple(matched_values))
