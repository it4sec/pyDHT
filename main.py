"""pyDHT application entry point and lifecycle orchestration."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
import uuid

import config
from includes import communications, debug, indexer, monitoring
from includes.dht import CandidateManager, DHTNode, bind_udp, dht_key_text, endpoint_allowed
from includes.peer import PeerClient, PeerError
from includes.storage import DatabaseWorker, JSONLWriter, StorageError, load_routing_snapshot

LOG = logging.getLogger("pydht")


def _retry_delay(attempt: int, base: int, maximum: int) -> int:
    exponent = max(0, min(attempt - 1, 30))
    return min(maximum, base * (2 ** exponent))


def _parse_dht_key(text: str) -> bytes | None:
    if not text.startswith("dht20:"):
        return None
    try:
        value = bytes.fromhex(text[6:])
    except ValueError:
        return None
    return value if len(value) == 20 else None


async def torrent_worker(worker_id: int, hash_queue: asyncio.Queue[bytes], candidates: CandidateManager,
                         db: DatabaseWorker, dht: DHTNode, peer_client: PeerClient, stopping: asyncio.Event) -> None:
    while not stopping.is_set():
        try:
            key = await hash_queue.get()
        except asyncio.CancelledError:
            return
        try:
            await _process_candidate(worker_id, key, candidates, db, dht, peer_client)
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.exception("torrent worker %d failed candidate %s", worker_id, key.hex())
        finally:
            hash_queue.task_done()


async def _process_candidate(worker_id: int, key: bytes, candidates: CandidateManager,
                             db: DatabaseWorker, dht: DHTNode, peer_client: PeerClient) -> None:
    key_text = dht_key_text(key)
    memory = candidates.state_for(key)
    observed_first = memory.first_seen_wall_ns if memory else time.time_ns()
    observed_last = memory.last_seen_wall_ns if memory else observed_first
    now_ns = time.time_ns()
    persistent = await db.upsert_candidate_seen(key_text, observed_first, observed_last)
    state = persistent.get("state")
    if state in {"complete", "unsupported"}:
        candidates.finish(key, recent=True)
        return
    if state == "fetch_failed":
        next_attempt = persistent.get("next_attempt_at")
        if next_attempt is None or int(next_attempt) > now_ns:
            candidates.finish(key, recent=True)
            return
    if not await db.mark_fetching(key_text, now_ns):
        candidates.finish(key, recent=True)
        return

    memory = candidates.state_for(key)
    hints = list(memory.peer_hints) if memory else []
    tried: set[tuple[str, int]] = set()
    errors: list[str] = []
    raw_info: bytes | None = None

    # announce_peer hints are valuable. An implied-port hint gets exactly one TCP attempt,
    # after which normal iterative get_peers is used.
    for ip, port, _implied in hints[: config.MAX_PEER_HINTS_PER_CANDIDATE]:
        endpoint = (ip, port)
        if endpoint in tried or not endpoint_allowed(ip, port, local_ips=dht.local_ips):
            continue
        tried.add(endpoint)
        try:
            result = await peer_client.fetch_metadata(endpoint, key)
        except (PeerError, OSError) as exc:
            errors.append(f"{ip}:{port} {type(exc).__name__}: {exc}")
            continue
        raw_info = result.raw_info
        break

    peers: list[tuple[str, int]] = []
    if raw_info is None:
        try:
            peers = await dht.iterative_get_peers(key)
        except Exception as exc:
            errors.append(f"get_peers {type(exc).__name__}: {exc}")
    # Re-read merged hints after the DHT lookup so an announce_peer that arrived while
    # this candidate was already processing is not lost.
    current_state = candidates.state_for(key)
    if current_state is not None:
        late = [(ip, port) for ip, port, _implied in current_state.peer_hints if (ip, port) not in tried]
        peers = late + [ep for ep in peers if ep not in late]

    attempts = len(tried)
    for endpoint in peers:
        if raw_info is not None or attempts >= min(config.MAX_PEERS_PER_TORRENT, config.MAX_METADATA_ATTEMPTS_PER_TORRENT):
            break
        if endpoint in tried:
            continue
        tried.add(endpoint)
        attempts += 1
        try:
            result = await peer_client.fetch_metadata(endpoint, key)
        except (PeerError, OSError) as exc:
            errors.append(f"{endpoint[0]}:{endpoint[1]} {type(exc).__name__}: {exc}")
            continue
        raw_info = result.raw_info
        break

    if raw_info is not None:
        torrent_uid = "btih:" + key.hex()
        try:
            torrent = indexer.parse_validated_info(raw_info, torrent_uid)
        except (indexer.IndexingError, ValueError) as exc:
            errors.append(f"indexing {type(exc).__name__}: {exc}")
        else:
            keyword_result = None
            if config.KEYWORD_MONITORING_ENABLED:
                keyword_result = monitoring.match_keywords(
                    torrent, tuple(config.KEYWORDS), case_sensitive=config.KEYWORD_CASE_SENSITIVE
                )
            await db.persist_torrent(torrent, key_text, keyword_result, time.time_ns())
            candidates.finish(key, recent=True)
            LOG.info("confirmed %s name=%r", torrent_uid, torrent.name)
            return

    latest = await db.candidate_state(key_text)
    attempt_no = int(latest.get("attempts", 1)) if latest else 1
    error_text = "; ".join(errors[-8:]) or "no usable metadata peer found"
    if attempt_no >= config.FETCH_RETRY_MAX_ATTEMPTS:
        await db.mark_fetch_failed(key_text, error_text, time.time_ns(), None)
    else:
        delay = _retry_delay(attempt_no, config.FETCH_RETRY_BASE_SECONDS, config.FETCH_RETRY_MAX_SECONDS)
        now = time.time_ns()
        await db.mark_fetch_failed(key_text, error_text, now, now + delay * 1_000_000_000)
    candidates.finish(key, recent=True)


async def retry_scheduler(db: DatabaseWorker, candidates: CandidateManager, stopping: asyncio.Event) -> None:
    while not stopping.is_set():
        try:
            due = await db.due_candidates(time.time_ns(), config.RETRY_SCAN_BATCH_SIZE)
            for text in due:
                key = _parse_dht_key(text)
                if key is not None:
                    candidates.submit(key, "durable_retry", retry=True)
            await asyncio.wait_for(stopping.wait(), timeout=config.RETRY_SCAN_INTERVAL)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            return


async def notification_scheduler(db: DatabaseWorker, stopping: asyncio.Event) -> None:
    while not stopping.is_set():
        try:
            if config.TELEGRAM_ENABLED:
                rows = await db.due_notifications(time.time_ns(), config.NOTIFICATION_SCAN_BATCH_SIZE)
                for row in rows:
                    if stopping.is_set():
                        break
                    await _send_notification_row(db, row)
            await asyncio.wait_for(stopping.wait(), timeout=config.NOTIFICATION_SCAN_INTERVAL)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            return


async def _send_notification_row(db: DatabaseWorker, row: dict) -> None:
    try:
        keywords = tuple(json.loads(row["keywords_json"]))
        matches = tuple(json.loads(row["matches_json"]))
    except (json.JSONDecodeError, TypeError):
        keywords, matches = (), ()
    torrent = indexer.IndexedTorrent(
        torrent_uid=row["torrent_uid"], name=row.get("name"), total_size=int(row.get("total_size") or 0),
        file_count=int(row.get("file_count") or 0), piece_length=row.get("piece_length"),
        metadata_size=int(row.get("metadata_size") or 0), raw_info=b"", files=(),
    )
    result = monitoring.KeywordResult(keywords, matches)
    message = communications.format_notification(torrent, result)
    success, error = await communications.send_once(message)
    attempt_no = int(row.get("attempts") or 0) + 1
    now = time.time_ns()
    if success:
        await db.mark_notification_result(row["torrent_uid"], success=True, now_ns=now, next_attempt_ns=None, error=None)
        return
    next_attempt = None
    if attempt_no < config.NOTIFICATION_RETRY_MAX_ATTEMPTS:
        delay = _retry_delay(attempt_no, config.NOTIFICATION_RETRY_BASE_SECONDS, config.NOTIFICATION_RETRY_MAX_SECONDS)
        next_attempt = now + delay * 1_000_000_000
    await db.mark_notification_result(row["torrent_uid"], success=False, now_ns=now, next_attempt_ns=next_attempt, error=error)


async def maintenance_scheduler(dht: DHTNode, stopping: asyncio.Event) -> None:
    while not stopping.is_set():
        try:
            await dht.maintenance_once()
            await asyncio.wait_for(stopping.wait(), timeout=config.DHT_MAINTENANCE_INTERVAL)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            return
        except Exception:
            LOG.exception("DHT maintenance iteration failed")


async def bep51_scheduler(dht: DHTNode, hash_queue: asyncio.Queue[bytes], stopping: asyncio.Event) -> None:
    while not stopping.is_set():
        try:
            await dht.bep51_once(hash_queue)
            await asyncio.wait_for(stopping.wait(), timeout=config.DHT_BEP51_GLOBAL_INTERVAL)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            return
        except Exception:
            LOG.exception("BEP-51 iteration failed")


async def fatal_monitor(db: DatabaseWorker, jsonl: JSONLWriter, stopping: asyncio.Event) -> None:
    while not stopping.is_set():
        if db.fatal_error is not None:
            LOG.critical("fatal SQLite worker failure: %s", db.fatal_error)
            stopping.set()
            return
        if jsonl.fatal_error is not None:
            LOG.critical("fatal JSONL writer failure: %s", jsonl.fatal_error)
            stopping.set()
            return
        await asyncio.sleep(0.5)


async def async_main() -> int:
    debug.initialize_logging()
    debug.validate_config()
    debug.ensure_paths()
    loop = asyncio.get_running_loop()
    run_id = str(uuid.uuid4())
    stopping = asyncio.Event()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stopping.set)
        except (NotImplementedError, RuntimeError):
            pass

    db = DatabaseWorker(loop)
    jsonl = JSONLWriter(run_id)
    db_started = False
    jsonl_started = False
    dht: DHTNode | None = None
    workers: list[asyncio.Task] = []
    schedulers: list[asyncio.Task] = []
    udp_bound = False

    try:
        db.start()
        db_started = True
        jsonl.start()
        jsonl_started = True

        restored_node_id, snapshot_records = load_routing_snapshot()
        node_id = restored_node_id or os.urandom(20)
        hash_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=config.HASH_QUEUE_SIZE)
        candidates = CandidateManager(hash_queue)
        dht = DHTNode(node_id, candidates, jsonl.emit)
        dht.routing.restore_contacts(snapshot_records)

        # Resolve configured DNS before UDP ingress so normal runtime keeps the documented thread model.
        dht.resolve_bootstrap_nodes()
        communications.prepare()
        peer_client = PeerClient(asyncio.Semaphore(config.MAX_PEER_CONNECTIONS), jsonl.emit)

        await bind_udp(dht)
        udp_bound = True
        LOG.info("pyDHT run_id=%s node_id=%s UDP=%s:%d", run_id, node_id.hex(), config.DHT_BIND_HOST, config.DHT_BIND_PORT)
        await dht.bootstrap()

        # Fixed torrent worker pool comes before retry/notification/BEP-51 schedulers.
        workers = [
            asyncio.create_task(
                torrent_worker(i, hash_queue, candidates, db, dht, peer_client, stopping),
                name=f"torrent-{i}",
            )
            for i in range(config.MAX_ACTIVE_TORRENTS)
        ]
        retry_task = asyncio.create_task(retry_scheduler(db, candidates, stopping), name="fetch-retry")
        notification_task = asyncio.create_task(notification_scheduler(db, stopping), name="notifications")
        maintenance_task = asyncio.create_task(maintenance_scheduler(dht, stopping), name="dht-maintenance")
        schedulers.extend([retry_task, notification_task, maintenance_task])
        if config.DHT_BEP51_ENABLED:
            schedulers.append(asyncio.create_task(bep51_scheduler(dht, hash_queue, stopping), name="bep51"))
        schedulers.append(asyncio.create_task(fatal_monitor(db, jsonl, stopping), name="fatal-monitor"))
        await stopping.wait()
    finally:
        # Approved shutdown sequence: schedulers -> UDP ingress -> torrent work -> snapshot -> JSONL -> DB -> writer.
        stopping.set()

        # 1-3: stop BEP-51, retry, notification and maintenance scheduling.
        for task in schedulers:
            task.cancel()
        if schedulers:
            await asyncio.gather(*schedulers, return_exceptions=True)

        # 4-6: close UDP ingress and thereby stop new discoveries/torrent submissions.
        if udp_bound and dht is not None:
            dht.close_ingress()

        # 7: cancel fixed torrent workers; active peer sessions have their own absolute deadline.
        for task in workers:
            task.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        # 8 is covered by cancellation of notification scheduler/send_once under its hard HTTP timeout.
        # 9: atomic routing snapshot.
        if jsonl_started and dht is not None:
            try:
                await jsonl.snapshot(dht.routing.snapshot_records())
            except Exception:
                LOG.exception("routing snapshot write failed during shutdown")

        # 10: flush network evidence.
        if jsonl_started:
            try:
                await jsonl.flush()
            except Exception:
                LOG.exception("JSONL flush failed during shutdown")

        # 11-12: all producers stopped; sentinel drains the DB FIFO before connection close.
        if db_started:
            try:
                await db.close()
            except Exception:
                LOG.exception("SQLite close failed")

        # 13: stop JSONL writer after final flush/snapshot.
        if jsonl_started:
            try:
                await jsonl.close()
            except Exception:
                LOG.exception("JSONL writer close failed")

    return 0 if db.fatal_error is None and jsonl.fatal_error is None else 1


def main() -> int:
    try:
        return asyncio.run(async_main())
    except (debug.ConfigurationError, StorageError, OSError) as exc:
        logging.getLogger("pydht").critical("startup failure: %s", exc)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
