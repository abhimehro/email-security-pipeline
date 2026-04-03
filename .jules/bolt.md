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
