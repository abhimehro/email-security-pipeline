## 2024-05-18 - [Optimize Regex Counting]
**Learning:** Python-level generator iteration with `sum(1 for _ in pattern.finditer(text))` has noticeable overhead when simple count of matches is needed.
**Action:** Use `len(pattern.findall(text))` instead of `sum(1 for _ in pattern.finditer(text))` when just counting matches, to execute entirely in C and speed up processing.

## 2026-03-07 - Tuple-based endswith optimization for string checking
**Learning:** When checking if a string is a suffix of a known set of strings (e.g., validating a domain against freemail providers), using `text.endswith(tuple_of_suffixes)` is both more correct and more performant than `any(substring in text for ...)`. The `in` operator can cause false positives on partial matches (e.g., `gmail.com.scam.com`), whereas `endswith` correctly validates suffixes. This method also delegates the loop to C for a significant speedup.
**Action:** When checking if a string ends with (or starts with) any of a set of known suffixes/prefixes, always use a pre-allocated class-level tuple with `str.endswith()` or `str.startswith()` instead of a Python-level `for` loop or `any()` generator expression.
