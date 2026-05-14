import sys
import time
from unittest.mock import MagicMock

# Mock dotenv
sys.modules['dotenv'] = MagicMock()

import os
sys.path.insert(0, os.getcwd())

from src.utils.caching import TTLCache

cache = TTLCache()
for i in range(1000):
    cache.put(f"key{i}", i)

start = time.monotonic()
for _ in range(100):
    for i in range(1000):
        cache.get(f"key{i}")
end1 = time.monotonic()

print(f"Individual get time: {end1 - start:.4f}s")

def get_many(self, keys):
    result = {}
    with self._lock:
        for key in keys:
            val = self._get_locked(key)
            if val is not None:
                result[key] = val
    return result

TTLCache.get_many = get_many

keys = [f"key{i}" for i in range(1000)]
start = time.monotonic()
for _ in range(100):
    cache.get_many(keys)
end2 = time.monotonic()

print(f"Batch get time: {end2 - start:.4f}s")
