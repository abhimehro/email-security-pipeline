## 2025-03-09 - [Performance Optimization: Pre-computing Magic Signature Prefixes]

**Learning:** In hot loops like file byte-signature detection (`_detect_file_type`), mapping over an array of tuples using `len(data) >= offset + len(sig)` and `data[offset:offset+len(sig)] == sig` incurs significant Python interpreter loop overhead.
**Action:** Group signatures by offset (e.g., all 0-offset signatures). Use `tuple()` to create a class-level variable, which allows the use of Python's highly optimized, C-level `bytes.startswith(tuple_of_bytes)`. This bypasses Python-level loops completely for the non-matching cases and results in up to ~6x speedups for file buffers that do not match the expected signatures.

## 2025-03-09 - [Performance Optimization: Bypassing `email.header` decoding for plain text]

**Learning:** `email.header.decode_header` incurs significant overhead (~44x slower) even when parsing plain strings that contain no encoded words. In this codebase's parsing pipeline, evaluating `make_header(decode_header(value))` for every header in every email creates a measurable bottleneck, particularly for long header chains like `Received`.
**Action:** Add an early return `if "=?" not in value:` before calling `decode_header`. Since the sequence `=?` is the required start of an RFC 2047 encoded word, its absence is a reliable and fast indicator that no decoding is necessary. This safely bypasses the expensive decoding function for the vast majority of headers, drastically speeding up email metadata parsing without altering behavior.

## 2025-03-09 - [Performance Optimization: Fast string substring checks before large regex operations]

**Learning:** For long bodies of text (like email contents), running a complex combined regex pattern with word boundaries (e.g. `\b`) is relatively slow compared to a fast literal substring check. In clean emails, executing the regex incurs overhead without yielding any matches.
**Action:** Use Python's highly-optimized C implementation of the `in` operator by checking `any(kw in text_lower for kw in SPAM_KEYWORDS_FAST)`. We bypass regex engine overhead by doing a quick substring sweep. For clean text blocks, this fast path avoids executing the regex entirely, yielding up to a ~14x speedup. However, ensure that the fast-path keywords are hardcoded literal strings and _not_ automatically parsed by stripping regex syntax, to avoid false negatives if more complex regex is added later.

## 2025-04-01 - [Performance Optimization: Faster Laplacian variance calculation with OpenCV]

**Learning:** For variance calculations on OpenCV arrays (e.g., `cv2.Laplacian` outputs), using NumPy's `.var()` method is slow compared to OpenCV's built-in `cv2.meanStdDev`.
**Action:** Replace `cv2.Laplacian(frame, cv2.CV_64F).var()` with `cv2.meanStdDev(cv2.Laplacian(frame, cv2.CV_64F))[1][0][0] ** 2`. This is significantly faster (~3x) and avoids falling back to NumPy's slower `.var()` method.

## 2025-05-15 - [Performance Optimization: Fast path for ANSI sequence stripping]

**Learning:** When sanitizing strings for logging or calculating visual lengths, repeatedly applying a regex `re.sub` for ANSI escape sequences is relatively slow (~300ns per call). In most cases, these strings do not contain ANSI sequences.
**Action:** Add a fast-path literal check `if "\x1b" in text:` before running the regex substitution. Python's C-level `in` operator takes only ~35ns to evaluate, resulting in a ~8x speedup for clean strings by avoiding the regex engine entirely.

## 2025-06-15 - [Performance Optimization: Faster character filtering with lazy translation tables]

**Learning:** When filtering out specific categories of non-printable Unicode characters from strings, using a list comprehension inside `"".join(...)` is relatively slow because it executes Python-level bytecode for every character in the string. Pre-computing a full translation table for `str.translate` is also not viable due to the massive memory and time overhead for all 1.1 million Unicode characters.
**Action:** Use `str.translate` with a lazy-evaluating dictionary subclass (implementing `__missing__` to lazily cache properties on first encounter). This approach pushes the filtering loop down to Python's optimized C implementation while avoiding the initialization cost of a full translation table, resulting in a ~20x speedup for filtering operations.

## 2025-07-20 - [Performance Optimization: Avoiding `np.mean` overhead for small arrays and native lists]

**Learning:** Using `np.mean()` on plain Python lists or very small NumPy arrays incurs significant overhead due to type checking, dispatching, and conversion. For example, `np.mean(avg_scores)` on a list of floats is ~6x slower than using native Python `sum(avg_scores) / len(avg_scores)`, and `np.mean(std)` on a 3x1 OpenCV array is ~10x slower than `float(std.sum()) / std.size`.
**Action:** For plain Python lists or small properties where native Python operations or direct NumPy sum/size are available, avoid `np.mean()`. Use `sum(lst) / len(lst)` for lists and `float(arr.sum()) / arr.size` for small NumPy arrays to bypass the function overhead entirely.

## 2025-08-01 - [Performance Optimization: Fast substring pre-check for complex regexes on large texts]

**Learning:** When applying complex regex patterns (like `HIDDEN_TEXT_PATTERN` which uses bounded quantifiers) to potentially large blocks of text (like email bodies), the regex engine can be significantly slow. In clean emails, running the regex engine is entirely wasted computation.
**Action:** Before running a complex regex search on large text blocks, check for required literal substrings (e.g., `if "font-size:" in html_lower or "color:" in html_lower:`) using Python's highly-optimized C implementation of the `in` operator. This bypasses the regex engine entirely for clean texts, providing a ~15-20x speedup depending on the text size, while maintaining exactly the same behavior for dirty texts.
