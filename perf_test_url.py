from urllib.parse import urlparse
import timeit

url = "https://user:password@www.example.com/path/to/resource?query=param#fragment"

def test_urlparse():
    parsed = urlparse(url)
    return parsed.netloc

print(f"urlparse netloc: {test_urlparse()}")

time_urlparse = timeit.timeit(test_urlparse, number=100000)

print(f"urlparse time: {time_urlparse:.4f}s")
