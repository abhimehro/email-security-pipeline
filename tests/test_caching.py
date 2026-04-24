import unittest
import time
from datetime import datetime, timedelta
from src.utils.caching import TTLCache

class TestTTLCache(unittest.TestCase):
    def test_initialization_valid(self):
        """Test TTLCache initialization with valid parameters."""
        cache = TTLCache(max_size=100, ttl_seconds=60)
        self.assertEqual(cache._max_size, 100)
        self.assertEqual(cache._ttl.total_seconds(), 60)

    def test_initialization_invalid(self):
        """Test TTLCache initialization with invalid parameters."""
        with self.assertRaises(ValueError):
            TTLCache(max_size=0)
        with self.assertRaises(ValueError):
            TTLCache(max_size=-1)
        with self.assertRaises(ValueError):
            TTLCache(ttl_seconds=0)
        with self.assertRaises(ValueError):
            TTLCache(ttl_seconds=-1)

    def test_put_get_basic(self):
        """Test basic put and get operations."""
        cache = TTLCache(max_size=10)
        cache.put("key1", "value1")
        self.assertEqual(cache.get("key1"), "value1")
        self.assertEqual(len(cache), 1)

    def test_put_overwrite_promotes(self):
        """Test that overwriting an existing key promotes it to most-recently-used."""
        cache = TTLCache(max_size=2)
        cache.put("a", 1)
        cache.put("b", 2)
        # 'a' is oldest, 'b' is newest.
        cache.put("a", 3) # Re-insert 'a', should promote it.
        # Now 'b' is oldest, 'a' is newest.
        cache.put("c", 4) # Evicts 'b'.
        self.assertIn("a", cache)
        self.assertIn("c", cache)
        self.assertNotIn("b", cache)

    def test_get_promotes(self):
        """Test that getting an existing key promotes it to most-recently-used."""
        cache = TTLCache(max_size=2)
        cache.put("a", 1)
        cache.put("b", 2)
        # 'a' is oldest.
        cache.get("a") # Promotes 'a'.
        # 'b' is now oldest.
        cache.put("c", 3) # Evicts 'b'.
        self.assertIn("a", cache)
        self.assertIn("c", cache)
        self.assertNotIn("b", cache)

    def test_size_eviction(self):
        """Test that the cache correctly evicts the least recently used item when full."""
        max_size = 5
        cache = TTLCache(max_size=max_size)
        for i in range(max_size + 2):
            cache.put(f"key{i}", i)

        self.assertEqual(len(cache), max_size)
        # key0 and key1 should be evicted (they were the first inserted and not accessed)
        self.assertNotIn("key0", cache)
        self.assertNotIn("key1", cache)
        self.assertIn("key2", cache)
        self.assertIn(f"key{max_size+1}", cache)

    def test_ttl_eviction_lazy_get(self):
        """Test lazy TTL eviction via get()."""
        cache = TTLCache(max_size=10, ttl_seconds=0.1)
        cache.put("key1", "value1")
        time.sleep(0.2)
        self.assertIsNone(cache.get("key1"))
        self.assertEqual(len(cache), 0)

    def test_ttl_eviction_lazy_contains(self):
        """Test lazy TTL eviction via __contains__."""
        cache = TTLCache(max_size=10, ttl_seconds=0.1)
        cache.put("key1", "value1")
        time.sleep(0.2)
        self.assertFalse("key1" in cache)
        self.assertEqual(len(cache), 0)

    def test_keys_filters_expired(self):
        """Test that keys() only returns non-expired keys."""
        cache = TTLCache(max_size=10, ttl_seconds=0.1)
        cache.put("live", 1)
        time.sleep(0.2)
        cache.put("fresh", 2)

        keys = cache.keys()
        self.assertIn("fresh", keys)
        self.assertNotIn("live", keys)
        self.assertEqual(len(keys), 1)

    def test_clear(self):
        """Test clearing the cache."""
        cache = TTLCache()
        cache.put("a", 1)
        cache.put("b", 2)
        cache.clear()
        self.assertEqual(len(cache), 0)
        self.assertEqual(cache.keys(), [])

    def test_none_value_not_supported(self):
        """Verify that None values are treated as cache misses, as documented."""
        cache = TTLCache()
        cache.put("key", None)
        self.assertIsNone(cache.get("key"))
        self.assertFalse("key" in cache)

if __name__ == "__main__":
    unittest.main()
