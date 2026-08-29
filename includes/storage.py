"""Persistent SQLite catalogue and bounded JSONL evidence writer."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import sqlite3
import threading
import time
import zlib
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

import config
from .indexer import IndexedTorrent
from .monitoring import KeywordResult

SCHEMA_VERSION = 1
JSONL_SCHEMA_VERSION = 1
LOG = logging.getLogger(__name__)


def load_routing_snapshot() -> tuple[bytes | None, list[dict[str, Any]]]:
    """Load the restart snapshot. Malformed lines are ignored; no network data enters SQLite."""
    path = Path(config.DHT_ROUTING_JSONL_PATH)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return None, []
    records: list[dict[str, Any]] = []
    local_node_id: bytes | None = None
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        records.append(record)
        if record.get("event") == "header":
            raw = record.get("local_node_id")
            if isinstance(raw, str):
                try:
                    candidate = bytes.fromhex(raw)
                except ValueError:
                    candidate = b""
                if len(candidate) == 20:
                    local_node_id = candidate
    return local_node_id, records


class StorageError(RuntimeError):
    pass


class DatabaseWorker:
    """One worker thread that exclusively owns one SQLite connection."""

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self._queue: queue.Queue[tuple[Callable[[sqlite3.Connection], Any] | None, asyncio.Future | None]] = queue.Queue(config.DB_QUEUE_SIZE)
        self._slots = asyncio.Semaphore(config.DB_QUEUE_SIZE)
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._startup_error: BaseException | None = None
        self._fatal_error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name="pydht-sqlite", daemon=False)

    def start(self) -> None:
        self._thread.start()
        self._ready.wait()
        if self._startup_error is not None:
            raise StorageError(f"SQLite startup failed: {self._startup_error}") from self._startup_error

    async def call(self, func: Callable[[sqlite3.Connection], Any]) -> Any:
        if self._fatal_error is not None:
            raise StorageError(f"SQLite worker failed: {self._fatal_error}") from self._fatal_error
        if self._stopped.is_set():
            raise StorageError("SQLite worker is stopped")
        await self._slots.acquire()
        future = self.loop.create_future()
        try:
            self._queue.put_nowait((func, future))
        except queue.Full as exc:
            self._slots.release()
            raise StorageError("SQLite queue capacity invariant violated") from exc
        try:
            return await future
        finally:
            self._slots.release()

    async def close(self) -> None:
        if self._stopped.is_set():
            return
        await self._slots.acquire()
        try:
            self._queue.put_nowait((None, None))
        finally:
            self._slots.release()
        self._thread.join()

    @property
    def fatal_error(self) -> BaseException | None:
        return self._fatal_error

    def _connect(self, *, recover_interrupted: bool = False) -> sqlite3.Connection:
        Path(config.DB_DIR).mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(config.SQLITE_PATH, timeout=config.DB_BUSY_TIMEOUT)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA busy_timeout = {int(config.DB_BUSY_TIMEOUT * 1000)}")
        conn.execute(f"PRAGMA journal_mode = {'WAL' if config.DB_WAL_ENABLED else 'DELETE'}")
        conn.execute(f"PRAGMA synchronous = {config.DB_SYNCHRONOUS.upper()}")
        self._migrate(conn)
        if recover_interrupted:
            now_ns = time.time_ns()
            conn.execute(
                """UPDATE torrent_candidates
                   SET state='fetch_failed', next_attempt_at=COALESCE(next_attempt_at, ?),
                       last_error=COALESCE(last_error, 'interrupted by restart')
                   WHERE state='fetching'""",
                (now_ns,),
            )
            conn.commit()
        return conn

    def _migrate(self, conn: sqlite3.Connection) -> None:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise StorageError(f"database schema {version} is newer than supported {SCHEMA_VERSION}")
        if version == 0:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS torrent_candidates (
                    dht_key TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_attempt INTEGER,
                    next_attempt_at INTEGER,
                    last_error TEXT,
                    torrent_uid TEXT
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS torrents (
                    torrent_uid TEXT PRIMARY KEY,
                    name TEXT,
                    total_size INTEGER,
                    file_count INTEGER,
                    piece_length INTEGER,
                    metadata_size INTEGER,
                    raw_info BLOB,
                    raw_info_encoding TEXT NOT NULL DEFAULT 'off',
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    status TEXT NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS files (
                    torrent_uid TEXT NOT NULL,
                    file_index INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    PRIMARY KEY (torrent_uid, file_index),
                    FOREIGN KEY (torrent_uid) REFERENCES torrents(torrent_uid) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    torrent_uid TEXT PRIMARY KEY,
                    keywords_json TEXT NOT NULL,
                    matches_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_attempt INTEGER,
                    next_attempt_at INTEGER,
                    sent_at INTEGER,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    FOREIGN KEY (torrent_uid) REFERENCES torrents(torrent_uid) ON DELETE CASCADE
                );
                PRAGMA user_version = 1;
                """
            )
            conn.commit()

    def _run(self) -> None:
        conn: sqlite3.Connection | None = None
        try:
            conn = self._connect(recover_interrupted=True)
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            self._stopped.set()
            return
        self._ready.set()
        try:
            while True:
                func, future = self._queue.get()
                if func is None:
                    break
                result = None
                operation_error: BaseException | None = None
                fatal = False
                for recovery_attempt in range(config.DB_REOPEN_RETRY_COUNT + 1):
                    try:
                        self._check_size()
                        result = func(conn)
                        self._check_size()
                        operation_error = None
                        break
                    except StorageError as exc:
                        operation_error = exc
                        fatal = True
                        break
                    except (sqlite3.DatabaseError, OSError) as exc:
                        operation_error = exc
                        try:
                            conn.rollback()
                        except sqlite3.Error:
                            pass
                        try:
                            conn.close()
                        except sqlite3.Error:
                            pass
                        if recovery_attempt >= config.DB_REOPEN_RETRY_COUNT:
                            fatal = True
                            break
                        time.sleep(config.DB_REOPEN_RETRY_DELAY)
                        try:
                            conn = self._connect()
                        except (sqlite3.DatabaseError, OSError, StorageError) as reopen_exc:
                            operation_error = reopen_exc
                            continue
                    except BaseException as exc:
                        operation_error = exc
                        break
                if operation_error is not None:
                    if future is not None:
                        self.loop.call_soon_threadsafe(_future_set_exception, future, operation_error)
                    if fatal:
                        self._fatal_error = operation_error
                        break
                elif future is not None:
                    self.loop.call_soon_threadsafe(_future_set_result, future, result)
        except BaseException as exc:
            self._fatal_error = exc
        finally:
            if conn is not None:
                try:
                    conn.commit()
                except sqlite3.Error:
                    pass
                finally:
                    try:
                        conn.close()
                    except sqlite3.Error:
                        pass
            self._stopped.set()

    def _check_size(self) -> None:
        total = 0
        base = Path(config.SQLITE_PATH)
        for path in (base, Path(str(base) + "-wal"), Path(str(base) + "-shm")):
            try:
                total += path.stat().st_size
            except FileNotFoundError:
                pass
        if total >= config.DATABASE_MAX_BYTES:
            raise StorageError("DATABASE_MAX_BYTES reached")

    async def upsert_candidate_seen(self, dht_key: str, first_seen_ns: int, last_seen_ns: int | None = None) -> dict[str, Any]:
        last_seen_ns = first_seen_ns if last_seen_ns is None else last_seen_ns
        def op(conn: sqlite3.Connection):
            conn.execute(
                """INSERT INTO torrent_candidates(dht_key,state,first_seen,last_seen)
                   VALUES(?, 'new', ?, ?)
                   ON CONFLICT(dht_key) DO UPDATE SET last_seen=MAX(last_seen, excluded.last_seen)""",
                (dht_key, first_seen_ns, last_seen_ns),
            )
            cursor = conn.execute("SELECT * FROM torrent_candidates WHERE dht_key=?", (dht_key,))
            row = cursor.fetchone()
            names = [d[0] for d in cursor.description]
            result = dict(zip(names, row))
            torrent_uid = result.get("torrent_uid")
            if torrent_uid:
                conn.execute("UPDATE torrents SET last_seen=MAX(last_seen, ?) WHERE torrent_uid=?", (last_seen_ns, torrent_uid))
            conn.commit()
            return result
        return await self.call(op)

    async def candidate_state(self, dht_key: str) -> dict[str, Any] | None:
        def op(conn: sqlite3.Connection):
            cursor = conn.execute("SELECT * FROM torrent_candidates WHERE dht_key=?", (dht_key,))
            row = cursor.fetchone()
            return dict(zip([d[0] for d in cursor.description], row)) if row else None
        return await self.call(op)

    async def mark_fetching(self, dht_key: str, now_ns: int) -> bool:
        def op(conn: sqlite3.Connection):
            cursor = conn.execute(
                """UPDATE torrent_candidates SET state='fetching', attempts=attempts+1,
                   last_attempt=?, next_attempt_at=NULL, last_error=NULL
                   WHERE dht_key=? AND state NOT IN ('complete','unsupported')""",
                (now_ns, dht_key),
            )
            conn.commit()
            return cursor.rowcount == 1
        return await self.call(op)

    async def mark_fetch_failed(self, dht_key: str, error: str, now_ns: int, next_attempt_ns: int | None) -> None:
        error = error[: config.MAX_INDEX_TEXT_LENGTH]
        def op(conn: sqlite3.Connection):
            conn.execute(
                """UPDATE torrent_candidates SET state='fetch_failed', last_attempt=?,
                   next_attempt_at=?, last_error=? WHERE dht_key=? AND state!='complete'""",
                (now_ns, next_attempt_ns, error, dht_key),
            )
            conn.commit()
        await self.call(op)

    async def mark_unsupported(self, dht_key: str, error: str | None = None) -> None:
        def op(conn: sqlite3.Connection):
            conn.execute("UPDATE torrent_candidates SET state='unsupported', last_error=?, next_attempt_at=NULL WHERE dht_key=?", (error, dht_key))
            conn.commit()
        await self.call(op)

    async def due_candidates(self, now_ns: int, limit: int) -> list[str]:
        def op(conn: sqlite3.Connection):
            rows = conn.execute(
                """SELECT dht_key FROM torrent_candidates
                   WHERE state='fetch_failed' AND next_attempt_at IS NOT NULL AND next_attempt_at<=?
                   ORDER BY next_attempt_at LIMIT ?""",
                (now_ns, limit),
            ).fetchall()
            return [row[0] for row in rows]
        return await self.call(op)

    async def persist_torrent(self, torrent: IndexedTorrent, dht_key: str, notification: KeywordResult | None, now_ns: int) -> None:
        raw_blob: bytes | None
        raw_encoding: str
        if config.RAW_INFO_STORAGE == "off":
            raw_blob, raw_encoding = None, "off"
        elif config.RAW_INFO_STORAGE == "raw":
            raw_blob, raw_encoding = torrent.raw_info, "raw"
        else:
            raw_blob, raw_encoding = zlib.compress(torrent.raw_info), "zlib"

        def op(conn: sqlite3.Connection):
            try:
                conn.execute("BEGIN")
                existing = conn.execute("SELECT first_seen FROM torrents WHERE torrent_uid=?", (torrent.torrent_uid,)).fetchone()
                first_seen = existing[0] if existing else now_ns
                conn.execute(
                    """INSERT INTO torrents(torrent_uid,name,total_size,file_count,piece_length,metadata_size,raw_info,raw_info_encoding,first_seen,last_seen,status)
                       VALUES(?,?,?,?,?,?,?,?,?,?, 'complete')
                       ON CONFLICT(torrent_uid) DO UPDATE SET
                         name=excluded.name,total_size=excluded.total_size,file_count=excluded.file_count,
                         piece_length=excluded.piece_length,metadata_size=excluded.metadata_size,
                         raw_info=excluded.raw_info,raw_info_encoding=excluded.raw_info_encoding,
                         last_seen=excluded.last_seen,status='complete'""",
                    (torrent.torrent_uid, torrent.name, torrent.total_size, torrent.file_count, torrent.piece_length,
                     torrent.metadata_size, raw_blob, raw_encoding, first_seen, now_ns),
                )
                conn.execute("DELETE FROM files WHERE torrent_uid=?", (torrent.torrent_uid,))
                conn.executemany(
                    "INSERT INTO files(torrent_uid,file_index,path,size) VALUES(?,?,?,?)",
                    [(torrent.torrent_uid, f.index, f.path, f.size) for f in torrent.files],
                )
                if notification is not None:
                    conn.execute(
                        """INSERT INTO notifications(torrent_uid,keywords_json,matches_json,status,created_at,next_attempt_at)
                           VALUES(?,?,?,'pending',?,?)
                           ON CONFLICT(torrent_uid) DO NOTHING""",
                        (torrent.torrent_uid, json.dumps(notification.keywords, ensure_ascii=False),
                         json.dumps(notification.matches, ensure_ascii=False), now_ns, now_ns),
                    )
                conn.execute(
                    "UPDATE torrent_candidates SET state='complete', torrent_uid=?, next_attempt_at=NULL, last_error=NULL WHERE dht_key=?",
                    (torrent.torrent_uid, dht_key),
                )
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        await self.call(op)

    async def due_notifications(self, now_ns: int, limit: int) -> list[dict[str, Any]]:
        def op(conn: sqlite3.Connection):
            cursor = conn.execute(
                """SELECT n.torrent_uid,n.keywords_json,n.matches_json,n.attempts,t.name,t.total_size,t.file_count,t.piece_length,t.metadata_size
                   FROM notifications n JOIN torrents t USING(torrent_uid)
                   WHERE n.status='pending' AND n.next_attempt_at IS NOT NULL AND n.next_attempt_at<=?
                   ORDER BY n.next_attempt_at LIMIT ?""",
                (now_ns, limit),
            )
            names = [d[0] for d in cursor.description]
            return [dict(zip(names, row)) for row in cursor.fetchall()]
        return await self.call(op)

    async def mark_notification_result(self, torrent_uid: str, *, success: bool, now_ns: int, next_attempt_ns: int | None, error: str | None) -> None:
        def op(conn: sqlite3.Connection):
            if success:
                conn.execute(
                    "UPDATE notifications SET status='sent', attempts=attempts+1,last_attempt=?,sent_at=?,next_attempt_at=NULL,last_error=NULL WHERE torrent_uid=?",
                    (now_ns, now_ns, torrent_uid),
                )
            else:
                status = "pending" if next_attempt_ns is not None else "failed"
                conn.execute(
                    "UPDATE notifications SET status=?,attempts=attempts+1,last_attempt=?,next_attempt_at=?,last_error=? WHERE torrent_uid=?",
                    (status, now_ns, next_attempt_ns, (error or "")[: config.MAX_INDEX_TEXT_LENGTH], torrent_uid),
                )
            conn.commit()
        await self.call(op)

    async def search(self, text: str, limit: int | None = None) -> list[dict[str, Any]]:
        limit = config.SEARCH_RESULT_LIMIT if limit is None else limit
        pattern = f"%{text}%"
        def op(conn: sqlite3.Connection):
            cursor = conn.execute(
                """SELECT DISTINCT t.torrent_uid,t.name,t.total_size,t.file_count,t.last_seen
                   FROM torrents t LEFT JOIN files f USING(torrent_uid)
                   WHERE t.name LIKE ? OR f.path LIKE ? ORDER BY t.last_seen DESC LIMIT ?""",
                (pattern, pattern, limit),
            )
            names = [d[0] for d in cursor.description]
            return [dict(zip(names, row)) for row in cursor.fetchall()]
        return await self.call(op)


def _future_set_result(future: asyncio.Future, value: Any) -> None:
    if not future.done():
        future.set_result(value)


def _future_set_exception(future: asyncio.Future, exc: BaseException) -> None:
    if not future.done():
        future.set_exception(exc)


class JSONLWriter:
    """One bounded, non-blocking evidence queue serviced by one writer thread."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue(config.DHT_JSONL_QUEUE_SIZE)
        self._thread = threading.Thread(target=self._run, name="pydht-jsonl", daemon=False)
        self._stop = threading.Event()
        self._started = threading.Event()
        self._fatal_error: BaseException | None = None
        self.dropped_events = 0
        self._last_drop_warning = 0.0

    def start(self) -> None:
        Path(config.DB_DIR).mkdir(parents=True, exist_ok=True)
        self._thread.start()
        self._started.wait()
        if self._fatal_error is not None:
            raise StorageError(f"JSONL writer startup failed: {self._fatal_error}") from self._fatal_error

    def emit(self, record: dict[str, Any]) -> bool:
        if self._fatal_error is not None or self._stop.is_set():
            return False
        clean = {key: value for key, value in record.items() if value is not None}
        clean.setdefault("schema_version", JSONL_SCHEMA_VERSION)
        clean.setdefault("timestamp_ns", time.time_ns())
        clean.setdefault("run_id", self.run_id)
        try:
            self._queue.put_nowait(("event", clean))
            return True
        except queue.Full:
            self.dropped_events += 1
            now = time.monotonic()
            if now - self._last_drop_warning >= config.JSONL_WARNING_INTERVAL:
                self._last_drop_warning = now
                LOG.warning("JSONL evidence queue full; dropped_events=%d", self.dropped_events)
            return False

    async def snapshot(self, records: list[dict[str, Any]]) -> None:
        if self._fatal_error is not None:
            raise StorageError(f"JSONL writer failed: {self._fatal_error}")
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        payload = (records, loop, future)
        while True:
            try:
                self._queue.put_nowait(("snapshot", payload))
                break
            except queue.Full:
                await asyncio.sleep(0.01)
        await future

    async def flush(self) -> None:
        if self._fatal_error is not None:
            raise StorageError(f"JSONL writer failed: {self._fatal_error}")
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        while True:
            try:
                self._queue.put_nowait(("flush", (loop, future)))
                break
            except queue.Full:
                await asyncio.sleep(0.01)
        await future

    async def close(self) -> None:
        if self._stop.is_set():
            return
        if self._fatal_error is not None:
            self._stop.set()
            self._thread.join()
            return
        await self.flush()
        self._stop.set()
        while True:
            try:
                self._queue.put_nowait(("stop", None))
                break
            except queue.Full:
                await asyncio.sleep(0.01)
        self._thread.join()

    @property
    def fatal_error(self) -> BaseException | None:
        return self._fatal_error

    def _rotate(self, path: Path) -> None:
        try:
            if path.stat().st_size < config.DHT_JSONL_MAX_BYTES:
                return
        except FileNotFoundError:
            return
        for index in range(config.DHT_JSONL_BACKUP_COUNT, 0, -1):
            src = path.with_name(path.name + f".{index}")
            dst = path.with_name(path.name + f".{index + 1}")
            if index == config.DHT_JSONL_BACKUP_COUNT:
                try:
                    src.unlink()
                except FileNotFoundError:
                    pass
            elif src.exists():
                os.replace(src, dst)
        if config.DHT_JSONL_BACKUP_COUNT > 0:
            os.replace(path, path.with_name(path.name + ".1"))

    def _write_snapshot(self, records: list[dict[str, Any]]) -> None:
        path = Path(config.DHT_ROUTING_JSONL_PATH)
        tmp = Path(str(path) + ".tmp")
        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                clean = {k: v for k, v in record.items() if v is not None}
                handle.write(json.dumps(clean, separators=(",", ":"), ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
        except (AttributeError, OSError):
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _open_event_file(self, path: Path):
        last_exc: BaseException | None = None
        for attempt in range(config.JSONL_REOPEN_RETRY_COUNT + 1):
            try:
                return path.open("a", encoding="utf-8", newline="\n")
            except OSError as exc:
                last_exc = exc
                if attempt < config.JSONL_REOPEN_RETRY_COUNT:
                    time.sleep(config.JSONL_REOPEN_RETRY_DELAY)
        raise StorageError(f"JSONL reopen failed: {last_exc}")

    def _write_event_with_recovery(self, path: Path, handle, line: str):
        last_exc: BaseException | None = None
        current = handle
        for attempt in range(config.JSONL_REOPEN_RETRY_COUNT + 1):
            try:
                if current is None:
                    current = self._open_event_file(path)
                current.write(line + "\n")
                return current
            except OSError as exc:
                last_exc = exc
                if current is not None:
                    try:
                        current.close()
                    except OSError:
                        pass
                current = None
                if attempt < config.JSONL_REOPEN_RETRY_COUNT:
                    time.sleep(config.JSONL_REOPEN_RETRY_DELAY)
        raise StorageError(f"JSONL write recovery failed: {last_exc}")

    def _snapshot_with_recovery(self, records: list[dict[str, Any]]) -> None:
        last_exc: BaseException | None = None
        for attempt in range(config.JSONL_REOPEN_RETRY_COUNT + 1):
            try:
                self._write_snapshot(records)
                return
            except OSError as exc:
                last_exc = exc
                if attempt < config.JSONL_REOPEN_RETRY_COUNT:
                    time.sleep(config.JSONL_REOPEN_RETRY_DELAY)
        raise StorageError(f"routing snapshot write recovery failed: {last_exc}")

    def _run(self) -> None:
        path = Path(config.DHT_NETWORK_JSONL_PATH)
        handle = None
        self._started.set()
        last_flush = time.monotonic()
        try:
            while True:
                try:
                    kind, payload = self._queue.get(timeout=config.DHT_JSONL_FLUSH_INTERVAL)
                except queue.Empty:
                    if handle is not None:
                        handle.flush()
                    last_flush = time.monotonic()
                    continue
                if kind == "stop":
                    break
                if kind == "event":
                    line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
                    handle = self._write_event_with_recovery(path, handle, line)
                    if time.monotonic() - last_flush >= config.DHT_JSONL_FLUSH_INTERVAL:
                        handle.flush()
                        last_flush = time.monotonic()
                    if handle.tell() >= config.DHT_JSONL_MAX_BYTES:
                        handle.flush()
                        handle.close()
                        handle = None
                        self._rotate(path)
                elif kind == "snapshot":
                    records, loop, future = payload
                    try:
                        self._snapshot_with_recovery(records)
                    except BaseException as exc:
                        loop.call_soon_threadsafe(_future_set_exception, future, exc)
                    else:
                        loop.call_soon_threadsafe(_future_set_result, future, None)
                elif kind == "flush":
                    loop, future = payload
                    try:
                        if handle is not None:
                            handle.flush()
                            os.fsync(handle.fileno())
                    except BaseException as exc:
                        loop.call_soon_threadsafe(_future_set_exception, future, exc)
                    else:
                        loop.call_soon_threadsafe(_future_set_result, future, None)
        except BaseException as exc:
            self._fatal_error = exc
            # Fail any queued waiters instead of leaving shutdown hanging.
            while True:
                try:
                    kind, payload = self._queue.get_nowait()
                except queue.Empty:
                    break
                if kind == "snapshot":
                    _, loop, future = payload
                    loop.call_soon_threadsafe(_future_set_exception, future, StorageError(str(exc)))
                elif kind == "flush":
                    loop, future = payload
                    loop.call_soon_threadsafe(_future_set_exception, future, StorageError(str(exc)))
        finally:
            if handle is not None:
                try:
                    handle.flush()
                    os.fsync(handle.fileno())
                finally:
                    handle.close()
