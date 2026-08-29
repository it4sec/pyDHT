import unittest

from includes.indexer import IndexedFile, IndexedTorrent
from includes.monitoring import match_keywords
from includes.communications import magnet_uri


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        self.torrent = IndexedTorrent(
            torrent_uid="btih:" + "ab" * 20,
            name="Ubuntu ISO",
            total_size=100,
            file_count=2,
            piece_length=16384,
            metadata_size=50,
            raw_info=b"x",
            files=(IndexedFile(0, "docs/ReadMe.TXT", 10), IndexedFile(1, "image.iso", 90)),
        )

    def test_casefold_match(self):
        result = match_keywords(self.torrent, ("ubuntu", "readme"))
        self.assertEqual(result.keywords, ("ubuntu", "readme"))

    def test_case_sensitive_mode(self):
        result = match_keywords(self.torrent, ("ubuntu",), case_sensitive=True)
        self.assertIsNone(result)

    def test_magnet_has_no_tracker(self):
        uri = magnet_uri(self.torrent.torrent_uid, self.torrent.name)
        self.assertIn("xt=urn:btih:", uri)
        self.assertNotIn("&tr=", uri)


if __name__ == "__main__":
    unittest.main()
