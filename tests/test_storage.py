import asyncio
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from includes.indexer import IndexedFile, IndexedTorrent
from includes.monitoring import KeywordResult
from includes.storage import DatabaseWorker, JSONLWriter, load_routing_snapshot


class DatabaseStorageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(config, "DB_DIR", self.root),
            patch.object(config, "SQLITE_PATH", self.root / "pydht.sqlite3"),
            patch.object(config, "DATABASE_MAX_BYTES", 100 * 1024 * 1024),
        ]
        for p in self.patches:
            p.start()
        self.db = DatabaseWorker(asyncio.get_running_loop())
        self.db.start()

    async def asyncTearDown(self):
        await self.db.close()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    async def test_schema_version_and_foreign_keys(self):
        def op(conn):
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
            return version, fk
        self.assertEqual(await self.db.call(op), (1, 1))

    async def test_candidate_retry_survives(self):
        key = "dht20:" + "01" * 20
        now = time.time_ns()
        await self.db.upsert_candidate_seen(key, now)
        await self.db.mark_fetching(key, now)
        await self.db.mark_fetch_failed(key, "x", now, now + 10)
        self.assertEqual(await self.db.due_candidates(now, 10), [])
        self.assertEqual(await self.db.due_candidates(now + 11, 10), [key])

    async def test_atomic_torrent_files_notification_candidate_completion(self):
        key = "dht20:" + "02" * 20
        uid = "btih:" + "02" * 20
        now = time.time_ns()
        await self.db.upsert_candidate_seen(key, now)
        torrent = IndexedTorrent(uid, "Name", 30, 2, 16384, 50, b"raw-info", (
            IndexedFile(0, "a", 10), IndexedFile(1, "b", 20)))
        match = KeywordResult(("name",), ("Name",))
        await self.db.persist_torrent(torrent, key, match, now)
        def op(conn):
            c = conn.execute("SELECT state,torrent_uid FROM torrent_candidates WHERE dht_key=?", (key,)).fetchone()
            t = conn.execute("SELECT name,total_size,raw_info_encoding FROM torrents WHERE torrent_uid=?", (uid,)).fetchone()
            f = conn.execute("SELECT COUNT(*) FROM files WHERE torrent_uid=?", (uid,)).fetchone()[0]
            n = conn.execute("SELECT status FROM notifications WHERE torrent_uid=?", (uid,)).fetchone()[0]
            return c, t, f, n
        c, t, f, n = await self.db.call(op)
        self.assertEqual(c, ("complete", uid))
        self.assertEqual(t[:2], ("Name", 30))
        self.assertEqual(f, 2)
        self.assertEqual(n, "pending")

    async def test_foreign_key_cascade(self):
        key = "dht20:" + "03" * 20
        uid = "btih:" + "03" * 20
        now = time.time_ns()
        await self.db.upsert_candidate_seen(key, now)
        torrent = IndexedTorrent(uid, "N", 1, 1, 1, 1, b"x", (IndexedFile(0, "x", 1),))
        await self.db.persist_torrent(torrent, key, None, now)
        def op(conn):
            conn.execute("DELETE FROM torrents WHERE torrent_uid=?", (uid,))
            conn.commit()
            return conn.execute("SELECT COUNT(*) FROM files WHERE torrent_uid=?", (uid,)).fetchone()[0]
        self.assertEqual(await self.db.call(op), 0)

    async def test_search_name_and_file_path(self):
        key = "dht20:" + "04" * 20
        uid = "btih:" + "04" * 20
        now = time.time_ns()
        await self.db.upsert_candidate_seen(key, now)
        torrent = IndexedTorrent(uid, "Alpha", 1, 1, 1, 1, b"x", (IndexedFile(0, "folder/beta.txt", 1),))
        await self.db.persist_torrent(torrent, key, None, now)
        self.assertEqual((await self.db.search("beta"))[0]["torrent_uid"], uid)


class JSONLStorageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            patch.object(config, "DB_DIR", self.root),
            patch.object(config, "DHT_NETWORK_JSONL_PATH", self.root / "dht_network.jsonl"),
            patch.object(config, "DHT_ROUTING_JSONL_PATH", self.root / "dht_routing.jsonl"),
            patch.object(config, "DHT_JSONL_FLUSH_INTERVAL", 0.01),
            patch.object(config, "DHT_JSONL_MAX_BYTES", 1024 * 1024),
        ]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    async def test_one_object_per_line_run_id_and_omit_none(self):
        writer = JSONLWriter("run-x")
        writer.start()
        writer.emit({"record_type": "peer", "event": "x", "optional": None})
        await writer.flush()
        await writer.close()
        lines = (self.root / "dht_network.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        obj = json.loads(lines[0])
        self.assertEqual(obj["run_id"], "run-x")
        self.assertNotIn("optional", obj)

    async def test_queue_saturation_drops_without_blocking(self):
        with patch.object(config, "DHT_JSONL_QUEUE_SIZE", 1):
            writer = JSONLWriter("run-x")
            self.assertTrue(writer.emit({"record_type": "x", "event": "one"}))
            self.assertFalse(writer.emit({"record_type": "x", "event": "two"}))
            self.assertEqual(writer.dropped_events, 1)
            writer._stop.set()  # never started; no thread to join

    async def test_atomic_routing_snapshot_and_restore(self):
        writer = JSONLWriter("run-x")
        writer.start()
        node_id = "ab" * 20
        records = [
            {"schema_version": 1, "record_type": "routing_snapshot", "event": "header", "local_node_id": node_id},
            {"schema_version": 1, "record_type": "routing_snapshot", "event": "contact", "node_id": "cd" * 20, "ip": "8.8.8.8", "udp_port": 6881},
        ]
        await writer.snapshot(records)
        restored, loaded = load_routing_snapshot()
        self.assertEqual(restored.hex(), node_id)
        self.assertEqual(len(loaded), 2)
        self.assertFalse((self.root / "dht_routing.jsonl.tmp").exists())
        await writer.close()


if __name__ == "__main__":
    unittest.main()
