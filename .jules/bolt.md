## 2024-05-18 - [Optimize Regex Counting]
**Learning:** Python-level generator iteration with `sum(1 for _ in pattern.finditer(text))` has noticeable overhead when simple count of matches is needed.
**Action:** Use `len(pattern.findall(text))` instead of `sum(1 for _ in pattern.finditer(text))` when just counting matches, to execute entirely in C and speed up processing.
