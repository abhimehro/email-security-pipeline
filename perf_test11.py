import timeit

def list_extend():
    a = []
    b = [f"item{i}" for i in range(10)]
    for i in range(100):
        a.extend([f"prefix: {x}" for x in b])
    return a

def list_comprehension():
    b = [f"item{i}" for i in range(10)]
    a = [f"prefix: {x}" for _ in range(100) for x in b]
    return a

print(f"extend: {timeit.timeit(list_extend, number=10000)}")
print(f"comprehension: {timeit.timeit(list_comprehension, number=10000)}")
