import sys
import time
from unittest.mock import MagicMock

# Mock dotenv
sys.modules['dotenv'] = MagicMock()

import os
sys.path.insert(0, os.getcwd())

from src.modules.spam_analyzer import SpamAnalyzer

def run_benchmark():
    config_mock = MagicMock()
    analyzer = SpamAnalyzer(config_mock)

    # Generate 10k urls, say 10 unique
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

    start = time.monotonic()
    for _ in range(10): # total 100k
        analyzer._check_urls(urls)
    end = time.monotonic()

    print(f"Time: {end - start:.4f}s")

run_benchmark()
