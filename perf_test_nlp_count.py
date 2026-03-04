import re
import timeit

text = "THIS IS A TEST " * 1000 + "URGENT ACTION REQUIRED! " * 50
pattern = re.compile(r'\b[A-Z]{4,}\b')

def test_finditer():
    return sum(1 for _ in pattern.finditer(text))

def test_findall():
    return len(pattern.findall(text))

print(f"finditer count: {test_finditer()}")
print(f"findall count: {test_findall()}")

time_finditer = timeit.timeit(test_finditer, number=10000)
time_findall = timeit.timeit(test_findall, number=10000)

print(f"finditer time: {time_finditer:.4f}s")
print(f"findall time: {time_findall:.4f}s")
print(f"Speedup: {time_finditer / time_findall:.2f}x")
