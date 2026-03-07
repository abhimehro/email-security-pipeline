## 2024-05-18 - [Optimize Regex Counting]
**Learning:** Python-level generator iteration with `sum(1 for _ in pattern.finditer(text))` has noticeable overhead when simple count of matches is needed.
**Action:** Use `len(pattern.findall(text))` instead of `sum(1 for _ in pattern.finditer(text))` when just counting matches, to execute entirely in C and speed up processing.

## 2025-03-07 - Tuple-based endswith optimization for string checking
**Learning:** In Python, replacing an `any(substring in text for substring in list)` generator expression with `text.endswith(tuple)` delegates the loop to highly-optimized C code, resulting in an order-of-magnitude performance improvement. This also avoids the overhead of creating generator objects and list allocations on every function call.
**Action:** When checking if a string ends with (or starts with) any of a set of known suffixes/prefixes, always use a pre-allocated class-level tuple with `str.endswith()` or `str.startswith()` instead of a Python-level `for` loop or `any()` generator expression.
