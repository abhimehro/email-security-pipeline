import timeit

setup = """
domain = "mail.yahoo.com"
FREEMAIL_PROVIDERS = (
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "mail.com",
    "protonmail.com",
)
FREEMAIL_PROVIDERS_DOT = tuple("." + p for p in FREEMAIL_PROVIDERS)
"""

test1 = "domain in FREEMAIL_PROVIDERS or any(domain.endswith(f'.{p}') for p in FREEMAIL_PROVIDERS)"
test2 = "domain in FREEMAIL_PROVIDERS or domain.endswith(FREEMAIL_PROVIDERS_DOT)"
test3 = "any(provider in domain for provider in FREEMAIL_PROVIDERS)"

print("test1:", timeit.timeit(test1, setup=setup, number=1000000))
print("test2 (tuple):", timeit.timeit(test2, setup=setup, number=1000000))
print("test3 (original):", timeit.timeit(test3, setup=setup, number=1000000))
