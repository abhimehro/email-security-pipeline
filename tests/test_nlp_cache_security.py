import unittest
import time
import hashlib
from src.modules.nlp_analyzer import NLPThreatAnalyzer
from src.utils.caching import TTLCache

# Mock Config
class MockConfig:
    def __init__(self):
        self.check_social_engineering = True
        self.check_urgency_markers = True
        self.check_authority_impersonation = True
        self.check_psychological_triggers = True
        self.nlp_threshold = 0.5
        self.nlp_model = 'distilbert-base-uncased'

class TestNLPCacheSecurity(unittest.TestCase):
    def setUp(self):
        self.config = MockConfig()
        self.analyzer = NLPThreatAnalyzer(self.config)

        # Mock the internal implementation to avoid needing torch
        # We replace the method on the instance
        self.call_count = 0
        self.analyzer._analyze_core_impl = self._mock_analyze_core_impl

        # Clear the TTLCache so each test starts with an empty cache
        self.analyzer._cache.clear()

    def _mock_analyze_core_impl(self, text):
        self.call_count += 1
        return {"threat_probability": 0.1, "confidence": 0.9}

    def test_cache_hit(self):
        text = "This is a test email."

        # First call
        result1 = self.analyzer.analyze_with_transformer(text)
        self.assertEqual(self.call_count, 1)

        # Second call
        result2 = self.analyzer.analyze_with_transformer(text)
        self.assertEqual(self.call_count, 1, "Should be cached and not call core impl again")
        self.assertEqual(result1, result2)

    def test_cache_key_is_hash(self):
        text = "Secret email content"
        self.analyzer.analyze_with_transformer(text)

        # Verify keys in cache are hashes
        keys = list(self.analyzer._cache.keys())
        self.assertEqual(len(keys), 1)

        key = keys[0]
        # SHA256 hexdigest is 64 chars
        self.assertEqual(len(key), 64)

        # Verify key is indeed the hash of the text
        expected_hash = hashlib.sha256(text.encode()).hexdigest()
        self.assertEqual(key, expected_hash)

        # Verify text is NOT in keys
        self.assertNotIn(text, keys)

    def test_cache_eviction(self):
        # Fill cache to max capacity (512 entries)
        for i in range(512):
            self.analyzer.analyze_with_transformer(f"Email {i}")

        self.assertEqual(len(self.analyzer._cache), 512)
        self.assertEqual(self.call_count, 512)

        # Add one more — oldest entry (Email 0) must be evicted
        self.analyzer.analyze_with_transformer("Email 512")

        self.assertEqual(len(self.analyzer._cache), 512, "Cache size should remain at max_size")

        # Verify oldest (Email 0) is gone
        hash0 = hashlib.sha256(b"Email 0").hexdigest()
        self.assertNotIn(hash0, self.analyzer._cache)

        # Verify newest is present
        hash512 = hashlib.sha256(b"Email 512").hexdigest()
        self.assertIn(hash512, self.analyzer._cache)

    def test_lru_behavior(self):
        # Add 3 items
        self.analyzer.analyze_with_transformer("Item 1")
        self.analyzer.analyze_with_transformer("Item 2")
        self.analyzer.analyze_with_transformer("Item 3")

        # Access Item 1 again (making it most recently used)
        self.analyzer.analyze_with_transformer("Item 1")

        # Verify order (in Python 3.7+ dicts preserve insertion order)
        # Re-inserting (pop + set) moves to end
        keys = list(self.analyzer._cache.keys())
        hash1 = hashlib.sha256(b"Item 1").hexdigest()
        self.assertEqual(keys[-1], hash1, "Item 1 should be last (most recent)")

    def test_ttl_eviction(self):
        """Entries older than TTL must be evicted on next access (lazy TTL)."""
        # Use a cache with a very short TTL so the test doesn't have to wait long
        short_ttl_cache = TTLCache(max_size=512, ttl_seconds=1)
        self.analyzer._cache = short_ttl_cache

        text = "TTL test email"
        text_hash = hashlib.sha256(text.encode()).hexdigest()

        # Populate the cache
        self.analyzer.analyze_with_transformer(text)
        self.assertIsNotNone(self.analyzer._cache.get(text_hash),
                             "Entry should be present before TTL expires")

        # Wait for TTL to expire
        time.sleep(1.1)

        # get() should now return None (lazy expiration) and remove the entry
        result = self.analyzer._cache.get(text_hash)
        self.assertIsNone(result, "Expired entry should return None after TTL")

        # Confirm the key is no longer accessible via the public API
        self.assertNotIn(text_hash, self.analyzer._cache)

if __name__ == '__main__':
    unittest.main()
