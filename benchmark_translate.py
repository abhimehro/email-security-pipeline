import time
import unicodedata

class LazyTranslateDict(dict):
    def __missing__(self, key):
        ch = chr(key)
        if ch.isprintable() or ch == "\t" or unicodedata.category(ch) == "Zs":
            self[key] = ch
            return ch
        self[key] = None
        return None

translator = LazyTranslateDict()

def sanitize_old(text):
    return "".join(
        [
            ch
            for ch in text
            if ch.isprintable() or ch == "\t" or unicodedata.category(ch) == "Zs"
        ]
    )

def sanitize_new(text):
    return text.translate(translator)

test_string = "Hello\x00World\tThis is a test string.\n" * 1000

start = time.perf_counter()
for _ in range(100):
    sanitize_old(test_string)
old_time = time.perf_counter() - start

start = time.perf_counter()
for _ in range(100):
    sanitize_new(test_string)
new_time = time.perf_counter() - start

print(f"Old: {old_time:.4f}s")
print(f"New: {new_time:.4f}s")
print(f"Speedup: {old_time / new_time:.2f}x")
