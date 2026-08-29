import hashlib
import unittest
from unittest.mock import patch

import config
from includes import bencode
from includes.indexer import IndexingError, parse_validated_info


class MetadataIndexTests(unittest.TestCase):
    def test_single_file_index(self):
        raw = bencode.encode({b"length": 123, b"name": b"file.bin", b"piece length": 16384})
        uid = "btih:" + hashlib.sha1(raw).hexdigest()
        result = parse_validated_info(raw, uid)
        self.assertEqual(result.total_size, 123)
        self.assertEqual(result.file_count, 1)
        self.assertEqual(result.files[0].path, "file.bin")

    def test_multifile_paths_and_sizes(self):
        raw = bencode.encode({
            b"name": b"root", b"piece length": 16384,
            b"files": [
                {b"length": 10, b"path": [b"a", b"one.txt"]},
                {b"length": 20, b"path": [b"b.bin"]},
            ],
        })
        result = parse_validated_info(raw, "btih:" + hashlib.sha1(raw).hexdigest())
        self.assertEqual(result.total_size, 30)
        self.assertEqual([f.path for f in result.files], ["a/one.txt", "b.bin"])

    def test_unsafe_path_component_rejected(self):
        raw = bencode.encode({b"name": b"root", b"files": [{b"length": 1, b"path": [b".."]}]})
        with self.assertRaises(IndexingError):
            parse_validated_info(raw, "btih:" + "00" * 20)

    def test_file_count_limit(self):
        raw = bencode.encode({b"name": b"root", b"files": [{b"length": 1, b"path": [b"x"]}, {b"length": 1, b"path": [b"y"]}]})
        with patch.object(config, "MAX_FILES_PER_TORRENT", 1), self.assertRaises(IndexingError):
            parse_validated_info(raw, "btih:" + "00" * 20)


if __name__ == "__main__":
    unittest.main()
