## 2024-05-18 - [Optimize Regex Counting]
**Learning:** Python-level generator iteration with `sum(1 for _ in pattern.finditer(text))` has noticeable overhead when simple count of matches is needed.
**Action:** Use `len(pattern.findall(text))` instead of `sum(1 for _ in pattern.finditer(text))` when just counting matches, to execute entirely in C and speed up processing.

## 2026-03-07 - Tuple-based endswith optimization for string checking
**Learning:** When checking if a string is a suffix of a known set of strings (e.g., validating a domain against freemail providers), using `text.endswith(tuple_of_suffixes)` is both more correct and more performant than `any(substring in text for ...)`. The `in` operator can cause false positives on partial matches (e.g., `gmail.com.scam.com`), whereas `endswith` correctly validates suffixes. This method also delegates the loop to C for a significant speedup.
**Action:** When checking if a string ends with (or starts with) any of a set of known suffixes/prefixes, always use a pre-allocated class-level tuple with `str.endswith()` or `str.startswith()` instead of a Python-level `for` loop or `any()` generator expression.

## 2025-03-10 - [Optimize Substring keyword matching]
**Learning:** Checking for substrings using generator loops `any(key in text for key in KEYWORDS)` is significantly slower than using compiled regular expressions `PATTERN.search(text)`.
**Action:** Replace `any()` generator loops with `re.search()` using compiled regular expression patterns when checking for a static set of keywords.
## 2025-03-14 - [Imports in class declarations]
**Learning:** Re.compile needs `re` imported correctly in Python. Attempting to dynamically import `re` within the class declaration itself but outside a function body raises a `NameError` inside list comprehensions inside `re.compile()`.
**Action:** Import modules at the top of the file to ensure they're available inside class-level property assignments.

## 2025-03-24 - [Optimize join strings with List Comprehension]
**Learning:** Using a list comprehension `"".join([c for c in text if ...])` is significantly faster (~30-40%) than a generator expression `"".join(c for c in text if ...)` for joining strings. This is because `join()` can pre-allocate the exact amount of memory needed when a list is passed, whereas with a generator, it has to dynamically resize the string buffer.
**Action:** When filtering characters to join into a string, use a list comprehension instead of a generator expression for better performance.
