
import pytest
import time
from src.modules.spam_analyzer import SpamAnalyzer
from src.utils.config import AnalysisConfig

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
    # Wait, my benchmark showed 0.02s for 5k without optimization?
    # Let's set a loose threshold, but enough to fail if it becomes extremely slow (e.g. O(N^2)).
    # The main point is that it runs successfully and correctly.
    # We can print the duration.

    print(f"Processed {len(urls)} URLs in {duration:.4f}s")
    assert duration < 1.0  # Should be well under 1s
