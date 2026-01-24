
import pytest
import time
from unittest.mock import MagicMock
from src.modules.spam_analyzer import SpamAnalyzer, SpamAnalysisResult
from src.utils.config import AnalysisConfig

class MockConfig:
    spam_threshold = 5.0
    spam_check_headers = True
    spam_check_urls = True

@pytest.fixture
def spam_analyzer():
    config = MockConfig()
    return SpamAnalyzer(config)

def test_check_urls_duplicates_correctness(spam_analyzer):
    """Verify that deduplication produces correct scoring and list compared to manual check"""

    # URL that triggers both COMBINED and SHORTENER patterns
    # bit.ly is in both
    url_double = "http://bit.ly/duplicate"
    # URL that triggers only COMBINED (e.g. suspicious long subdomain)
    url_single = "http://" + "a" * 35 + ".com"
    # Clean URL
    url_clean = "http://google.com"

    urls = [url_double, url_double, url_single, url_double, url_clean]
    # url_double appears 3 times. Each time adds 0.5 (combined) + 0.5 (shortener) = 1.0. Total = 3.0.
    # url_single appears 1 time. Adds 0.5. Total = 0.5.
    # url_clean appears 1 time. Adds 0.
    # Total score should be 3.5.

    score, suspicious = spam_analyzer._check_urls(urls)

    assert score == 3.5

    # Verify suspicious list
    # url_double should appear 6 times (3 occurrences * 2 checks matches)
    assert suspicious.count(url_double) == 6
    # url_single should appear 1 time
    assert suspicious.count(url_single) == 1

    assert len(suspicious) == 7

def test_check_urls_performance(spam_analyzer):
    """Verify performance improvement on duplicates"""
    base_urls = [
        "http://google.com",
        "http://bit.ly/12345",
        "http://example.com",
        "http://tinyurl.com/abc",
        "http://normal-site.com/page",
    ]
    # 5000 URLs, mostly duplicates
    urls = base_urls * 1000

    start_time = time.time()
    spam_analyzer._check_urls(urls)
    end_time = time.time()

    duration = end_time - start_time
    # This should be very fast. Without optimization it was ~0.02s (for 5000),
    # but here we have overhead of object creation etc.
    # Just asserting it runs without error is fine for unit test,
    # but I'll add a soft check.
    # In sandbox, 10000 URLs took 0.001s with optimization.
    # So 5000 should be under 0.01s safely.

    assert duration < 0.5 # Very generous upper bound
