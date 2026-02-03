import unittest
import hashlib
from src.modules.nlp_analyzer import NLPThreatAnalyzer

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

        # Clear cache
        self.analyzer._cache = {}

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
        # Fill cache with 1024 items
        for i in range(1024):
            self.analyzer.analyze_with_transformer(f"Email {i}")

        self.assertEqual(len(self.analyzer._cache), 1024)
        self.assertEqual(self.call_count, 1024)

        # Add one more
        self.analyzer.analyze_with_transformer("Email 1024")

        self.assertEqual(len(self.analyzer._cache), 1024, "Cache size should remain 1024")

        # Verify oldest (Email 0) is gone
        hash0 = hashlib.sha256(b"Email 0").hexdigest()
        self.assertNotIn(hash0, self.analyzer._cache)

        # Verify newest is present
        hash1024 = hashlib.sha256(b"Email 1024").hexdigest()
        self.assertIn(hash1024, self.analyzer._cache)

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

if __name__ == '__main__':
    unittest.main()
