import re
import timeit

text = "This is a test. " * 1000 + "URGENT ACTION REQUIRED! " * 50 + "CLICK HERE " * 50
pattern = re.compile(r'\b(urgent|immediate|action required|act now|click here)\b', re.IGNORECASE)

def test_finditer():
    return sum(1 for _ in pattern.finditer(text))

def test_findall():
    return len(pattern.findall(text))

print(f"finditer count: {test_finditer()}")
print(f"findall count: {test_findall()}")

time_finditer = timeit.timeit(test_finditer, number=100000)
time_findall = timeit.timeit(test_findall, number=100000)

print(f"finditer time: {time_finditer:.4f}s")
print(f"findall time: {time_findall:.4f}s")
print(f"Speedup: {time_finditer / time_findall:.2f}x")
