import pytest
from src.utils.caching import TTLCache

def test_get_many():
    cache = TTLCache()
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)

    assert cache.get_many(["a", "b", "d"]) == {"a": 1, "b": 2}

def test_get_many_empty():
    cache = TTLCache()
    assert cache.get_many(["a", "b"]) == {}
    assert cache.get_many([]) == {}
