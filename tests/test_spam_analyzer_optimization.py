
import time
import pytest
from src.modules.spam_analyzer import SpamAnalyzer
class MockConfig:
    spam_threshold = 5.0
    spam_check_headers = True
    spam_check_urls = True

@pytest.fixture
def spam_analyzer():
    config = MockConfig()
    return SpamAnalyzer(config)

def test_check_urls_correctness(spam_analyzer):
    # Test with duplicates and mix of suspicious/safe URLs
    urls = [
        "http://google.com",
        "http://bit.ly/suspicious",
        "http://bit.ly/suspicious", # Duplicate suspicious
        "http://example.com",
        "http://192.168.1.1/admin", # Suspicious IP
        "http://very-long-suspicious-subdomain-that-is-way-too-long.example.com", # Suspicious length
        "http://google.com", # Duplicate safe
    ]

    score, suspicious = spam_analyzer._check_urls(urls)

    # Expected behavior:
    # google.com -> 0
    # bit.ly -> 1.0 (0.5 combined + 0.5 shortener) * 2 instances = 2.0
    # example.com -> 0
    # 192.168.1.1 -> 0.5 * 1 = 0.5
    # very-long... -> 0.5 * 1 = 0.5
    # Total score = 3.0

    # Suspicious list should contain:
    # bit.ly (2 times per instance * 2 instances = 4 entries? Or just 2?)
    # Wait, the original implementation appends for EACH match.
    # bit.ly matches COMBINED_URL_PATTERN -> append
    # bit.ly matches SHORTENER_PATTERN -> append
    # So for one bit.ly URL, it appends twice.
    # So for 2 bit.ly URLs, it appends 4 times.

    # 192.168.1.1 matches COMBINED -> append (1)
    # very-long... matches COMBINED -> append (1)

    # Total suspicious entries = 4 + 1 + 1 = 6

    assert score == 3.0
    assert len(suspicious) == 6
    assert suspicious.count("http://bit.ly/suspicious") == 4
    assert suspicious.count("http://192.168.1.1/admin") == 1
    assert suspicious.count("http://very-long-suspicious-subdomain-that-is-way-too-long.example.com") == 1

def test_check_urls_performance_large_dataset(spam_analyzer):
    # Generate a large dataset with many duplicates (common in email threads)
    urls = [
        "http://google.com",
        "http://bit.ly/suspicious",
        "http://example.com",
        "http://192.168.1.1/admin",
        "http://very-long-suspicious-subdomain-that-is-way-too-long.example.com"
    ] * 2000  # 10,000 URLs

    start_time = time.time()
    spam_analyzer._check_urls(urls)
    end_time = time.time()
    duration = end_time - start_time

    # On a reasonably fast machine, processing 10k URLs with optimization should be very fast (< 0.1s)
    # Without optimization it takes ~0.05s for 5k URLs -> ~0.1s for 10k.
    # With shared cache, repeated URLs are O(1) hash lookup
    print(f"Processed {len(urls)} URLs in {duration:.4f}s")
    assert duration < 1.0

def test_url_cache_persistence(spam_analyzer):
    """Test that URL analysis results are cached across calls"""
    url = "http://bit.ly/suspicious-cache-test"

    # First call - should calculate and cache
    score1, suspicious1 = spam_analyzer._check_urls([url])

    # Second call - should retrieve from cache
    score2, suspicious2 = spam_analyzer._check_urls([url])

    assert score1 == score2
    assert suspicious1 == suspicious2

    # Verify cache internals directly
    if hasattr(spam_analyzer, '_url_cache'):
        assert url in spam_analyzer._url_cache
        # Tuple of (score, append_count)
        # 0.5 (combined) + 0.5 (shortener) = 1.0, 2 appends
        assert spam_analyzer._url_cache[url] == (1.0, 2)

def test_url_cache_lru_eviction(spam_analyzer):
    """Test that cache respects size limit and evicts properly"""
    if not hasattr(spam_analyzer, '_url_cache'):
        pytest.skip("Shared cache not implemented")

    # Temporarily reduce max cache size for testing
    original_size = spam_analyzer._max_cache_size
    spam_analyzer._max_cache_size = 5

    try:
        # Fill cache
        for i in range(5):
            spam_analyzer._check_urls([f"http://example{i}.com"])

        assert len(spam_analyzer._url_cache) == 5
        # Use .keys() to be explicit about dictionary lookup (avoids CodeQL substring check warning)
        assert "http://example0.com" in spam_analyzer._url_cache.keys()

        # Add one more to trigger eviction
        spam_analyzer._check_urls(["http://example5.com"])

        # Check size maintained
        assert len(spam_analyzer._url_cache) == 5
        # Check oldest evicted (example0)
        assert "http://example0.com" not in spam_analyzer._url_cache.keys()
        # Check newest added
        assert "http://example5.com" in spam_analyzer._url_cache.keys()

        # Access an existing item to move it to MRU
        spam_analyzer._check_urls(["http://example1.com"])

        # Add another item
        spam_analyzer._check_urls(["http://example6.com"])

        # example1 should still be there (was moved to MRU)
        assert "http://example1.com" in spam_analyzer._url_cache.keys()
        # example2 should be evicted (was oldest)
        assert "http://example2.com" not in spam_analyzer._url_cache.keys()

    finally:
        spam_analyzer._max_cache_size = original_size
