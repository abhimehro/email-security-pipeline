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

    def test_put_get_basic(self):
        """Test basic put and get operations."""
        self.cache.put("key1", "value1")
        self.assertEqual(self.cache.get("key1"), "value1")
        self.assertEqual(len(self.cache), 1)

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

    def test_size_eviction(self):
        """Test size-based eviction."""
        max_size = 5
        cache = TTLCache(max_size=max_size)
        for i in range(max_size + 2):
            cache.put(f"k{i}", i)
        self.assertEqual(len(cache), max_size)
        self._verify_eviction(cache, [f"k{i}" for i in range(2, 7)], ["k0", "k1"])

    def test_ttl_eviction_lazy(self):
        """Test lazy TTL eviction."""
        cache = TTLCache(max_size=10, ttl_seconds=0.1)
        cache.put("k", "v")
        time.sleep(0.2)
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

    def test_clear(self):
        """Test clear()."""
        self.cache.put("a", 1)
        self.cache.clear()
        self.assertEqual(len(self.cache), 0)


if __name__ == "__main__":
    unittest.main()
