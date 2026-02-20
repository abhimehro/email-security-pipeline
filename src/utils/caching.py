"""
Thread-safe LRU cache with TTL (Time-To-Live) expiration.

PATTERN RECOGNITION: This combines two complementary eviction policies:
  - Size-based (LRU): discards the least-recently-used entry when the cache
    exceeds max_size, preventing unbounded memory growth in long-running daemons.
  - Time-based (TTL): lazily removes entries whose age exceeds ttl_seconds at
    the next access, preventing stale analysis results from persisting forever.

SECURITY STORY: Callers should hash sensitive input before using it as a cache
key so that raw user content (e.g., email body text) never appears in the key
space.  SHA-256 is the recommended hash; 64-char hex digests are easy to audit.

MAINTENANCE WISDOM: This module is intentionally free of external dependencies
so it can be reused safely across any module that needs bounded caching without
importing the full project dependency tree.
"""

import threading
from datetime import datetime, timedelta
from typing import Any, List, Optional


class TTLCache:
    """
    Thread-safe LRU cache with configurable size limit and TTL expiration.

    Entries are evicted when:
    - The cache exceeds *max_size* — the oldest/least-recently-used entry is
      removed first (insertion-order LRU via Python dict).
    - An entry's age exceeds *ttl_seconds* — it is removed lazily on the next
      ``get`` or ``__contains__`` call for that key.

    Note: ``None`` values are not supported; ``get`` returns ``None`` to signal
    a cache miss (absent or expired).

    Args:
        max_size:    Maximum number of live entries (default 512).
        ttl_seconds: Seconds before an entry is considered stale (default 3600).
    """

    def __init__(self, max_size: int = 512, ttl_seconds: int = 3600) -> None:
        if max_size <= 0:
            raise ValueError(f"max_size must be a positive integer, got {max_size}")
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be a positive integer, got {ttl_seconds}")
        self._store: dict = {}          # key -> (value, datetime)
        self._max_size = max_size
        self._ttl = timedelta(seconds=ttl_seconds)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def get(self, key: str) -> Optional[Any]:
        """
        Return the cached value for *key*, or ``None`` if absent or expired.

        TEACHING MOMENT: Accessing a live entry promotes it to
        most-recently-used position (LRU promotion), so frequently-accessed
        items are evicted last when the cache is under pressure.
        """
        with self._lock:
            return self._get_locked(key)

    def put(self, key: str, value: Any) -> None:
        """
        Store *value* under *key*, evicting the oldest entry when over capacity.

        Re-inserting an existing key promotes it to most-recently-used.
        """
        with self._lock:
            # Remove first so re-insertion places the key at the tail (newest)
            self._store.pop(key, None)
            self._store[key] = (value, datetime.now())
            # Evict oldest entries until we are within the size budget
            while len(self._store) > self._max_size:
                try:
                    self._store.pop(next(iter(self._store)))
                except (StopIteration, KeyError):  # pragma: no cover
                    break

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._store.clear()

    # ------------------------------------------------------------------
    # Read-only dict-compatibility helpers (used by tests / introspection)
    # ------------------------------------------------------------------

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return self._get_locked(key) is not None

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def keys(self) -> List[str]:
        """Return non-expired keys in LRU order (oldest first, newest last)."""
        now = datetime.now()
        with self._lock:
            return [
                k for k, (_, ts) in self._store.items()
                if now - ts < self._ttl
            ]

    # ------------------------------------------------------------------
    # Private helper (must be called with _lock already held)
    # ------------------------------------------------------------------

    def _get_locked(self, key: str) -> Optional[Any]:
        if key not in self._store:
            return None
        value, timestamp = self._store[key]
        if datetime.now() - timestamp >= self._ttl:
            del self._store[key]   # Lazy TTL eviction
            return None
        # Promote to most-recently-used by moving to the tail of the dict
        del self._store[key]
        self._store[key] = (value, timestamp)
        return value
