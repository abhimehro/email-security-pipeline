import time
import unittest

from src.utils.caching import TTLCache


class TestTTLCache(unittest.TestCase):
    def setUp(self):
        self.cache = TTLCache(max_size=10, ttl_seconds=3600)

    def test_initialization_valid(self):
        """Test TTLCache initialization with valid parameters."""
        cache = TTLCache(max_size=100, ttl_seconds=60)
        self.assertEqual(cache._max_size, 100)
        self.assertEqual(cache._ttl, 60.0)

    def test_initialization_invalid(self):
        """Test TTLCache initialization with invalid parameters."""
        for params in [
            {"max_size": 0},
            {"max_size": -1},
            {"ttl_seconds": 0},
            {"ttl_seconds": -1},
        ]:
            with self.subTest(params=params):
                with self.assertRaises(ValueError):
                    TTLCache(**params)

    def test_basic_get_put_clear(self):
        """Test basic get, put, and clear operations."""
        # Test put and get
        self.cache.put("key1", "value1")
        self.assertEqual(self.cache.get("key1"), "value1")
        self.assertEqual(len(self.cache), 1)

        # Test missing key returns None
        self.assertIsNone(self.cache.get("nonexistent"))

        # Test clear
        self.cache.clear()
        self.assertIsNone(self.cache.get("key1"))
        self.assertEqual(len(self.cache), 0)

    def _verify_eviction(self, cache, expected_present, expected_absent):
        for k in expected_present:
            self.assertIn(k, cache)
        for k in expected_absent:
            self.assertNotIn(k, cache)

    def test_put_overwrite_promotes(self):
        """Test that overwriting an existing key promotes it to most-recently-used."""
        cache = TTLCache(max_size=2)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("a", 3)
        cache.put("c", 4)
        self._verify_eviction(cache, ["a", "c"], ["b"])

    def test_get_promotes(self):
        """Test that getting an existing key promotes it to most-recently-used."""
        cache = TTLCache(max_size=2)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.get("a")
        cache.put("c", 3)
        self._verify_eviction(cache, ["a", "c"], ["b"])

    def test_lru_eviction(self):
        """Test LRU eviction when cache exceeds max_size."""
        max_size = 5
        cache = TTLCache(max_size=max_size)

        # Fill cache to max_size
        for i in range(max_size):
            cache.put(f"k{i}", i)

        # Add one more to trigger eviction of the oldest (k0)
        cache.put("k_new", 99)

        self.assertEqual(len(cache), max_size)
        self.assertIsNone(cache.get("k0"))  # Evicted
        self.assertEqual(cache.get("k1"), 1)  # Still present
        self.assertEqual(cache.get("k_new"), 99)  # Newly added

    def test_ttl_expiration(self):
        """Test TTL expiration and lazy eviction."""
        cache = TTLCache(max_size=10, ttl_seconds=0.1)
        cache.put("k", "v")
        self.assertEqual(cache.get("k"), "v")
        self.assertIn("k", cache)

        # Wait for TTL to expire
        time.sleep(0.2)

        # Should return None and lazily evict on get or __contains__
        self.assertNotIn("k", cache)
        self.assertIsNone(cache.get("k"))
        self.assertEqual(len(cache), 0)

    def test_keys_filtering(self):
        """Test keys() filtering."""
        cache = TTLCache(max_size=10, ttl_seconds=0.1)
        cache.put("old", 1)
        time.sleep(0.2)
        cache.put("new", 2)
        keys = cache.keys()
        self.assertIn("new", keys)
        self.assertNotIn("old", keys)


if __name__ == "__main__":
    unittest.main()
