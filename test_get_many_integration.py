import sys
import time
from unittest.mock import MagicMock

# Mock dotenv
sys.modules['dotenv'] = MagicMock()

import os
sys.path.insert(0, os.getcwd())

from src.utils.caching import TTLCache

def get_many(self, keys):
    result = {}
    with self._lock:
        for key in keys:
            val = self._get_locked(key)
            if val is not None:
                result[key] = val
    return result

TTLCache.get_many = get_many

from src.modules.spam_analyzer import SpamAnalyzer

def check_urls_batch(self, urls):
    score = 0.0
    suspicious = []

    cached_results = self.url_cache.get_many(urls)

    for url in urls:
        cached = cached_results.get(url)
        if cached is not None:
            url_score, append_count = cached
            score += url_score
            if append_count > 0:
                suspicious.extend([url] * append_count)
            continue

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc

            current_url_score = 0.0
            append_count = 0

            if self.COMBINED_URL_PATTERN.search(domain):
                current_url_score += 0.5
                append_count += 1

            score += current_url_score
            if append_count > 0:
                suspicious.extend([url] * append_count)

            self.url_cache.put(url, (current_url_score, append_count))

        except Exception:
            self.url_cache.put(url, (0.0, 0))

    return score, suspicious


SpamAnalyzer._check_urls_batch = check_urls_batch

def run_benchmark():
    config_mock = MagicMock()
    analyzer = SpamAnalyzer(config_mock)

    base_urls = [
        "http://example.com/page1",
        "https://google.com/search?q=test",
        "http://suspicious-domain-123.com/login",
        "http://normal.org",
        "https://bank-update-secure.com/auth",
        "http://site.com/a",
        "http://site.com/b",
        "http://site.com/c",
        "http://site.com/d",
        "http://site.com/e",
    ]
    urls = base_urls * 1000  # 10,000 URLs

    # warm up cache
    analyzer._check_urls(base_urls)
    analyzer._check_urls_batch(base_urls)

    start = time.monotonic()
    for _ in range(10): # total 100k
        analyzer._check_urls(urls)
    end = time.monotonic()

    start2 = time.monotonic()
    for _ in range(10): # total 100k
        analyzer._check_urls_batch(urls)
    end2 = time.monotonic()

    print(f"Original Time: {end - start:.4f}s")
    print(f"Batched Time: {end2 - start2:.4f}s")

run_benchmark()
