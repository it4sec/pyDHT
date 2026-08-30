import unittest

from includes import bencode


class BencodeTests(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        value = {b"a": 1, b"b": [b"x", 2], b"c": {b"d": b"e"}}
        raw = bencode.encode(value)
        self.assertEqual(
            bencode.decode(raw, max_depth=10, max_items=100, max_string_length=100),
            value,
        )

    def test_dictionary_encoding_is_sorted(self):
        self.assertEqual(bencode.encode({b"b": 1, b"a": 2}), b"d1:ai2e1:bi1ee")

    def test_reject_trailing_data(self):
        with self.assertRaises(bencode.BencodeError):
            bencode.decode(b"i1ee", max_depth=3, max_items=10, max_string_length=10)

    def test_decode_prefix_tracks_consumed_bytes(self):
        value, consumed = bencode.decode_prefix(b"d1:ai1eex", max_depth=5, max_items=10, max_string_length=10)
        self.assertEqual(value, {b"a": 1})
        self.assertEqual(consumed, 8)

    def test_reject_noncanonical_integer(self):
        for raw in (b"i01e", b"i-0e", b"ie"):
            with self.subTest(raw=raw), self.assertRaises(bencode.BencodeError):
                bencode.decode(raw, max_depth=3, max_items=10, max_string_length=10)

    def test_depth_limit(self):
        with self.assertRaises(bencode.BencodeError):
            bencode.decode(b"llli1eeee", max_depth=1, max_items=20, max_string_length=10)

    def test_item_limit_counts_dictionary_keys(self):
        with self.assertRaises(bencode.BencodeError):
            bencode.decode(b"d1:ai1e1:bi2ee", max_depth=5, max_items=3, max_string_length=10)

    def test_string_limit(self):
        with self.assertRaises(bencode.BencodeError):
            bencode.decode(b"4:abcd", max_depth=3, max_items=10, max_string_length=3)

    def test_reject_unsorted_dictionary(self):
        with self.assertRaises(bencode.BencodeError):
            bencode.decode(b"d1:bi1e1:ai2ee", max_depth=5, max_items=20, max_string_length=10)

    def test_tolerant_mode_accepts_unsorted_dictionary(self):
        value = bencode.decode(
            b"d1:bi1e1:ai2ee",
            max_depth=5,
            max_items=20,
            max_string_length=10,
            require_sorted_keys=False,
        )
        self.assertEqual(value, {b"b": 1, b"a": 2})

    def test_tolerant_mode_still_rejects_duplicate_dictionary_keys(self):
        with self.assertRaises(bencode.BencodeError):
            bencode.decode(
                b"d1:ai1e1:ai2ee",
                max_depth=5,
                max_items=20,
                max_string_length=10,
                require_sorted_keys=False,
            )


if __name__ == "__main__":
    unittest.main()
