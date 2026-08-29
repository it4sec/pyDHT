"""Logging, configuration validation and runtime diagnostics."""
from __future__ import annotations

import ipaddress
import logging
import math
from pathlib import Path

import config


class ConfigurationError(ValueError):
    pass


def initialize_logging() -> None:
    level = getattr(logging, str(config.LOG_LEVEL).upper(), None)
    if not isinstance(level, int):
        raise ConfigurationError("LOG_LEVEL is invalid")
    logging.basicConfig(level=level, format=config.LOG_FORMAT)


def _number(name: str, *, allow_zero: bool = False) -> None:
    value = getattr(config, name)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ConfigurationError(f"{name} must be a finite number")
    if value < 0 if allow_zero else value <= 0:
        raise ConfigurationError(f"{name} must be {'non-negative' if allow_zero else 'positive'}")


def _integer(name: str, *, allow_zero: bool = False) -> None:
    value = getattr(config, name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{name} must be an integer")
    if value < 0 if allow_zero else value <= 0:
        raise ConfigurationError(f"{name} must be {'non-negative' if allow_zero else 'positive'}")


def validate_config() -> None:
    try:
        client_version = config.DHT_CLIENT_VERSION.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ConfigurationError("DHT_CLIENT_VERSION must be ASCII text") from exc
    if len(client_version) != 4:
        raise ConfigurationError("DHT_CLIENT_VERSION must encode to exactly 4 ASCII bytes")

    if not isinstance(config.DHT_BEP51_RESPONSE_INTERVAL, int) or isinstance(config.DHT_BEP51_RESPONSE_INTERVAL, bool) or not (0 <= config.DHT_BEP51_RESPONSE_INTERVAL <= 21600):
        raise ConfigurationError("DHT_BEP51_RESPONSE_INTERVAL must be an integer in 0..21600")

    try:
        bind = ipaddress.ip_address(config.DHT_BIND_HOST)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("DHT_BIND_HOST must be an IP literal") from exc
    if bind.version != 4:
        raise ConfigurationError("v0.1 DHT_BIND_HOST must be IPv4")

    integer_positive = (
        "DHT_BIND_PORT", "DHT_QUERY_BURST", "DHT_MAX_PENDING_REQUESTS", "DHT_LOOKUP_PARALLELISM",
        "MAX_DHT_QUERIES_PER_TORRENT", "DHT_RECEIVE_MAX_BYTES", "DHT_ROUTING_BAD_AFTER_FAILURES",
        "HASH_QUEUE_SIZE", "MAX_ACTIVE_TORRENTS", "MAX_PEER_HINTS_PER_CANDIDATE", "RECENT_HASH_CACHE_SIZE",
        "MAX_METADATA_ATTEMPTS_PER_TORRENT", "MAX_PEER_CONNECTIONS", "MAX_PEERS_PER_TORRENT",
        "METADATA_REQUEST_PIPELINE", "MAX_METADATA_SIZE", "MAX_PEER_MESSAGE_SIZE", "MAX_BENCODE_DEPTH",
        "MAX_BENCODE_ITEMS", "MAX_BENCODE_STRING_LENGTH", "MAX_FILES_PER_TORRENT", "MAX_PATH_COMPONENTS",
        "MAX_INDEX_TEXT_LENGTH", "MAX_EVIDENCE_TEXT_LENGTH", "BEP51_NODE_STATE_MAX",
        "BEP51_MAX_SAMPLES_PER_RESPONSE", "DHT_PEER_STORE_MAX_INFOHASHES", "DHT_PEER_STORE_MAX_PEERS_PER_HASH",
        "DB_QUEUE_SIZE", "DATABASE_MAX_BYTES", "RETRY_SCAN_BATCH_SIZE", "FETCH_RETRY_MAX_ATTEMPTS",
        "DHT_JSONL_QUEUE_SIZE", "DHT_JSONL_MAX_BYTES", "TELEGRAM_MESSAGE_MAX_CHARS",
        "TELEGRAM_HTTP_MAX_RESPONSE_BYTES", "TELEGRAM_MAX_MATCH_LINES", "NOTIFICATION_RETRY_MAX_ATTEMPTS",
        "NOTIFICATION_SCAN_BATCH_SIZE", "SEARCH_RESULT_LIMIT",
    )
    for name in integer_positive:
        _integer(name)

    integer_nonnegative = ("DB_REOPEN_RETRY_COUNT", "DHT_JSONL_BACKUP_COUNT", "JSONL_REOPEN_RETRY_COUNT")
    for name in integer_nonnegative:
        _integer(name, allow_zero=True)

    numeric_positive = (
        "DHT_MAX_REQUESTS_PER_SECOND", "DHT_QUERY_TIMEOUT", "DHT_LOOKUP_DEADLINE", "DHT_ROUTING_GOOD_TTL",
        "DHT_ROUTING_REFRESH_INTERVAL", "DHT_MAINTENANCE_INTERVAL", "DHT_BOOTSTRAP_RETRY_INTERVAL",
        "RECENT_HASH_TTL", "PEER_CONNECT_TIMEOUT", "PEER_HANDSHAKE_TIMEOUT", "PEER_SESSION_TIMEOUT",
        "METADATA_TIMEOUT", "DHT_BEP51_GLOBAL_INTERVAL", "DHT_BEP51_UNSUPPORTED_BACKOFF", "BEP51_NODE_STATE_TTL",
        "DHT_PEER_STORE_TTL", "DHT_TOKEN_ROTATION_INTERVAL", "DHT_TOKEN_VALIDITY", "DB_BUSY_TIMEOUT",
        "RETRY_SCAN_INTERVAL", "FETCH_RETRY_BASE_SECONDS", "FETCH_RETRY_MAX_SECONDS", "DHT_JSONL_FLUSH_INTERVAL",
        "JSONL_WARNING_INTERVAL", "TELEGRAM_HTTP_TIMEOUT", "NOTIFICATION_RETRY_BASE_SECONDS",
        "NOTIFICATION_RETRY_MAX_SECONDS", "NOTIFICATION_SCAN_INTERVAL",
    )
    for name in numeric_positive:
        _number(name)

    for name in ("DB_REOPEN_RETRY_DELAY", "JSONL_REOPEN_RETRY_DELAY"):
        _number(name, allow_zero=True)

    if not (1 <= config.DHT_BIND_PORT <= 65535):
        raise ConfigurationError("DHT_BIND_PORT out of range")
    if config.DHT_RECEIVE_MAX_BYTES < 1024:
        raise ConfigurationError("DHT_RECEIVE_MAX_BYTES must be at least 1024")
    if config.MAX_PEER_MESSAGE_SIZE < 16 * 1024 + 1024:
        raise ConfigurationError("MAX_PEER_MESSAGE_SIZE is too small for BEP-9 messages")
    if config.RAW_INFO_STORAGE not in {"off", "raw", "zlib"}:
        raise ConfigurationError("RAW_INFO_STORAGE must be one of: off, raw, zlib")
    if str(config.DB_SYNCHRONOUS).upper() not in {"OFF", "NORMAL", "FULL", "EXTRA"}:
        raise ConfigurationError("invalid DB_SYNCHRONOUS")
    if not (0.0 <= config.BEP51_QUEUE_LOW_WATERMARK < config.BEP51_QUEUE_HIGH_WATERMARK <= 1.0):
        raise ConfigurationError("invalid BEP-51 queue watermarks")
    if config.DHT_TOKEN_VALIDITY > 2 * config.DHT_TOKEN_ROTATION_INTERVAL:
        raise ConfigurationError("DHT_TOKEN_VALIDITY cannot exceed two token rotation intervals")
    if config.FETCH_RETRY_BASE_SECONDS > config.FETCH_RETRY_MAX_SECONDS:
        raise ConfigurationError("FETCH_RETRY_BASE_SECONDS cannot exceed FETCH_RETRY_MAX_SECONDS")
    if config.NOTIFICATION_RETRY_BASE_SECONDS > config.NOTIFICATION_RETRY_MAX_SECONDS:
        raise ConfigurationError("NOTIFICATION_RETRY_BASE_SECONDS cannot exceed NOTIFICATION_RETRY_MAX_SECONDS")
    if config.TELEGRAM_MESSAGE_MAX_CHARS > 4096:
        raise ConfigurationError("TELEGRAM_MESSAGE_MAX_CHARS cannot exceed Telegram sendMessage limit")

    try:
        prefix = config.PEER_ID_PREFIX.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ConfigurationError("PEER_ID_PREFIX must be ASCII text") from exc
    if len(prefix) > 20:
        raise ConfigurationError("PEER_ID_PREFIX too long")

    if not isinstance(config.DHT_BOOTSTRAP_NODES, (tuple, list)) or not config.DHT_BOOTSTRAP_NODES:
        raise ConfigurationError("DHT_BOOTSTRAP_NODES must not be empty")
    for item in config.DHT_BOOTSTRAP_NODES:
        if not isinstance(item, (tuple, list)) or len(item) != 2 or not isinstance(item[0], str) or not item[0]:
            raise ConfigurationError("invalid DHT bootstrap node")
        if isinstance(item[1], bool) or not isinstance(item[1], int) or not (1 <= item[1] <= 65535):
            raise ConfigurationError("invalid DHT bootstrap port")

    if not isinstance(config.KEYWORDS, (tuple, list)) or any(not isinstance(k, str) or not k for k in config.KEYWORDS):
        raise ConfigurationError("KEYWORDS must contain non-empty strings")
    if config.TELEGRAM_ENABLED and (not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID):
        raise ConfigurationError("Telegram is enabled but credentials are missing")


def ensure_paths() -> None:
    Path(config.DB_DIR).mkdir(parents=True, exist_ok=True)
