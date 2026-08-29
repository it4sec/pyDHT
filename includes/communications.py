"""Telegram message construction and one-attempt asynchronous transport."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import urllib.parse

import config
from .indexer import IndexedTorrent
from .monitoring import KeywordResult

_TELEGRAM_HOST = "api.telegram.org"
_TELEGRAM_IPS: list[str] = []
_TELEGRAM_IP_INDEX = 0


def prepare() -> None:
    """Resolve Telegram endpoints synchronously during startup, before UDP ingress."""
    global _TELEGRAM_IPS, _TELEGRAM_IP_INDEX
    if not config.TELEGRAM_ENABLED:
        _TELEGRAM_IPS = []
        _TELEGRAM_IP_INDEX = 0
        return
    ips: list[str] = []
    try:
        infos = socket.getaddrinfo(_TELEGRAM_HOST, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        infos = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in ips:
            ips.append(ip)
    _TELEGRAM_IPS = ips
    _TELEGRAM_IP_INDEX = 0


def magnet_uri(torrent_uid: str, name: str | None = None) -> str:
    if not torrent_uid.startswith("btih:"):
        raise ValueError("only confirmed v1 btih torrent IDs are supported")
    infohash = torrent_uid[5:]
    if len(infohash) != 40 or any(ch not in "0123456789abcdef" for ch in infohash):
        raise ValueError("invalid btih torrent UID")
    uri = f"magnet:?xt=urn:btih:{infohash}"
    if name:
        uri += "&dn=" + urllib.parse.quote(name, safe="")
    return uri


def format_notification(torrent: IndexedTorrent, result: KeywordResult) -> str:
    lines = [
        "pyDHT keyword match",
        f"Name: {torrent.name or '(unknown)'}",
        f"Size: {torrent.total_size}",
        f"Keywords: {', '.join(result.keywords)}",
        magnet_uri(torrent.torrent_uid, torrent.name),
    ]
    if result.matches:
        lines.append("Matches:")
        lines.extend(f"- {value}" for value in result.matches[: config.TELEGRAM_MAX_MATCH_LINES])
    text = "\n".join(lines)
    return text[: config.TELEGRAM_MESSAGE_MAX_CHARS]


async def _read_chunked(reader: asyncio.StreamReader, timeout: float, max_bytes: int) -> bytes:
    chunks = bytearray()
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout)
        size = int(line.split(b";", 1)[0].strip(), 16)
        if size == 0:
            await asyncio.wait_for(reader.readline(), timeout)
            return bytes(chunks)
        if size < 0 or len(chunks) + size > max_bytes:
            raise ValueError("HTTP response body exceeds configured limit")
        chunks.extend(await asyncio.wait_for(reader.readexactly(size), timeout))
        await asyncio.wait_for(reader.readexactly(2), timeout)


async def send_once(message: str) -> tuple[bool, str | None]:
    """Perform exactly one Telegram HTTPS request attempt."""
    if not config.TELEGRAM_ENABLED:
        return False, "telegram disabled"
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        return False, "telegram credentials missing"
    global _TELEGRAM_IP_INDEX
    host = _TELEGRAM_HOST
    if not _TELEGRAM_IPS:
        return False, "telegram endpoint unresolved"
    ip = _TELEGRAM_IPS[_TELEGRAM_IP_INDEX % len(_TELEGRAM_IPS)]
    path = f"/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    body = urllib.parse.urlencode({"chat_id": config.TELEGRAM_CHAT_ID, "text": message}).encode("utf-8")
    ssl_context = ssl.create_default_context()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, family=socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET,
                                    ssl=ssl_context, server_hostname=host),
            timeout=config.TELEGRAM_HTTP_TIMEOUT,
        )
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body
        writer.write(request)
        await asyncio.wait_for(writer.drain(), config.TELEGRAM_HTTP_TIMEOUT)
        status_line = await asyncio.wait_for(reader.readline(), config.TELEGRAM_HTTP_TIMEOUT)
        parts = status_line.decode("iso-8859-1", errors="replace").strip().split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return False, "invalid HTTP response"
        status = int(parts[1])
        headers: dict[str, str] = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), config.TELEGRAM_HTTP_TIMEOUT)
            if line in (b"\r\n", b"\n", b""):
                break
            key, _, value = line.decode("iso-8859-1").partition(":")
            headers[key.strip().lower()] = value.strip()
        if headers.get("transfer-encoding", "").lower() == "chunked":
            response_body = await _read_chunked(reader, config.TELEGRAM_HTTP_TIMEOUT, config.TELEGRAM_HTTP_MAX_RESPONSE_BYTES)
        elif "content-length" in headers:
            length = min(int(headers["content-length"]), config.TELEGRAM_HTTP_MAX_RESPONSE_BYTES)
            response_body = await asyncio.wait_for(reader.readexactly(length), config.TELEGRAM_HTTP_TIMEOUT)
        else:
            response_body = await asyncio.wait_for(reader.read(config.TELEGRAM_HTTP_MAX_RESPONSE_BYTES), config.TELEGRAM_HTTP_TIMEOUT)
        if 200 <= status < 300:
            try:
                payload = json.loads(response_body.decode("utf-8"))
                if payload.get("ok") is True:
                    return True, None
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            return False, "telegram response did not confirm success"
        return False, f"telegram HTTP status {status}"
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        if _TELEGRAM_IPS:
            _TELEGRAM_IP_INDEX = (_TELEGRAM_IP_INDEX + 1) % len(_TELEGRAM_IPS)
        return False, f"telegram transport error: {type(exc).__name__}: {exc}"
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
