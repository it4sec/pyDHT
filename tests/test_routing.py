import time
import unittest
from unittest.mock import patch

from includes.dht import DHT_K, Contact, RoutingTable, xor_distance


def nid(n):
    return n.to_bytes(20, "big")


class RoutingTests(unittest.TestCase):
    def test_xor_distance(self):
        self.assertEqual(xor_distance(nid(1), nid(3)), 2)

    def test_direct_response_becomes_good(self):
        table = RoutingTable(nid(0))
        c = table.observe(nid(1), "8.8.8.8", 6881, direct_response=True)
        self.assertEqual(c.state(), "GOOD")

    def test_indirect_contact_is_questionable(self):
        table = RoutingTable(nid(0))
        c = table.observe(nid(1), "8.8.8.8", 6881, direct_response=False)
        self.assertEqual(c.state(), "QUESTIONABLE")

    def test_bucket_splits_only_when_local_id_in_range(self):
        table = RoutingTable(nid(0))
        for i in range(1, DHT_K + 2):
            table.observe(nid(i), "8.8.8.8", 6000 + i, direct_response=True)
        self.assertGreater(len(table.buckets), 1)

    def test_full_far_bucket_uses_replacement_not_split(self):
        local = nid(0)
        table = RoutingTable(local)
        # Force one split then fill the high bucket, which does not contain local ID.
        for i in range(1, DHT_K + 2):
            table.observe(nid(i), "8.8.8.8", 6000 + i, direct_response=True)
        high = table.buckets[-1]
        base = high.low
        for i in range(DHT_K):
            table.observe(nid(base + i), "8.8.4.4", 7000 + i, direct_response=True)
        before = len(table.buckets)
        table.observe(nid(base + DHT_K + 1), "1.1.1.1", 8000, direct_response=False)
        self.assertEqual(len(table.buckets), before)
        self.assertLessEqual(len(high.replacements), DHT_K)

    def test_bad_node_replaced_after_failures(self):
        table = RoutingTable(nid(0))
        for i in range(1, DHT_K + 1):
            table.observe(nid(i), "8.8.8.8", 6000 + i, direct_response=True)
        # ensure a replacement exists in same bucket after enough splitting settles
        victim = table.all_contacts()[0]
        bucket = table._bucket_for(victim.node_id)
        replacement = Contact(nid(int.from_bytes(victim.node_id, 'big') + 1000), "1.1.1.1", 9999)
        if bucket.contains(replacement.node_id):
            bucket.replacements.append(replacement)
            table.mark_failure(victim.node_id)
            table.mark_failure(victim.node_id)
            self.assertIn(replacement, bucket.contacts)

    def test_snapshot_restore_is_questionable(self):
        table = RoutingTable(nid(0))
        table.observe(nid(1), "8.8.8.8", 6881, direct_response=True)
        records = table.snapshot_records()
        restored = RoutingTable(nid(0))
        restored.restore_contacts(records)
        c = restored.find(nid(1))
        self.assertIsNotNone(c)
        self.assertEqual(c.state(), "QUESTIONABLE")


if __name__ == "__main__":
    unittest.main()
