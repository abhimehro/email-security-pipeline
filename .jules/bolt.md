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

## 2024-05-20 - Optimize OpenCV Video Frame Extraction with Hybrid Seek/Grab

**Learning:** In OpenCV, jumping to specific frames in a video using `cv2.VideoCapture.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)` incurs significant decoding overhead, making it exceptionally slow for small jumps. However, sequentially skipping frames using `cap.grab()` without decoding them via `cap.retrieve()` or `cap.read()` is much faster for short distances.
**Action:** Implemented a hybrid approach for sampling frames. If the frame jump distance is less than or equal to a defined threshold (e.g., 30 frames), use sequential `cap.grab()` calls. For larger jumps, fall back to `cap.set()`. This significantly reduces extraction time for videos sampled with smaller step sizes while maintaining efficiency for large gaps.

## 2025-08-01 - [Performance Optimization: Faster metric tracking with defaultdict]

**Learning:** For high-throughput tracking loops that perform simple increments (e.g., `dict[key] += 1`), using `collections.Counter` incurs unnecessary overhead. Benchmark results show that `collections.defaultdict(int)` is ~2.5x faster.
**Action:** Replace `Counter` with `defaultdict(int)` for tracking high-frequency metrics like threat detections and errors. When using `defaultdict` as a default value in a dataclass, wrap it in a lambda (e.g., `field(default_factory=lambda: defaultdict(int))`) since `default_factory` requires a zero-argument callable.

## 2025-08-01 - [Performance Optimization: Fast substring pre-check for complex regexes on large texts]

**Learning:** When applying complex regex patterns (like `HIDDEN_TEXT_PATTERN` which uses bounded quantifiers) to potentially large blocks of text (like email bodies), the regex engine can be significantly slow. In clean emails, running the regex engine is entirely wasted computation.
**Action:** Before running a complex regex search on large text blocks, check for required literal substrings (e.g., `if re.search(r"font-size:|color:", html_body, re.I):`) to bypass the complex regex engine for clean texts. This avoids the overhead of full-string lowercasing and provides a ~15-20x speedup depending on the text size, while maintaining exactly the same behavior for dirty texts.

## 2025-08-01 - [Performance Optimization: Faster Video Frame Extraction using Hybrid Seeking]

**Learning:** In `src/modules/media_analyzer.py`, seeking to specific video frames via `cap.set(cv2.CAP_PROP_POS_FRAMES, i)` incurs significant decoding overhead and is slow for small forward jumps. However, for large jumps, `cap.grab()` becomes slower than `cap.set()`.
**Action:** Implement a hybrid approach: use sequential `cap.grab()` for small intervals (e.g., <= 30 frames) to avoid redundant decoding, and fall back to `cap.set()` for larger intervals.

## 2025-05-15 - Global URL Caching in SpamAnalyzer

**Learning:** Recreating a URL cache on every email analysis call misses the opportunity to optimize for common URLs (social media, footers) across a batch. Using a class-level TTLCache provides thread-safe, bounded persistence that survives across method calls.
**Action:** Implemented instance-level TTLCache in SpamAnalyzer and refactored \_check_urls to leverage it, resulting in a ~2.7x speedup for typical batches with repeated URLs.

## 2024-05-24 - Avoid cap.set() for small jumps in OpenCV

**Learning:** In OpenCV, `cap.set(cv2.CAP_PROP_POS_FRAMES, i)` incurs heavy decoding overhead for small frame jumps.
**Action:** Always use a hybrid approach (like `_extract_frames_sampled`) that uses sequential `cap.grab()` for small intervals and `cap.set()` for large ones instead of manual `cap.set()` loops.

## 2025-05-08 - Fast Caching Optimization

**Learning:** Python's `datetime.now()` with `timedelta` objects incur high instantiation and garbage collection overhead, which compounds in hot cache eviction loops like `TTLCache`.
**Action:** Replace `datetime.now()` and `timedelta` with `time.monotonic()` and float arithmetic. This avoids the object creation overhead and is more resilient to system clock adjustments.
## 2026-05-14 - Optimize dict.get in loop
**Learning:** Checking nested structures or dict getters (`attachment.get(...)`) unconditionally outside of a branch or guard logic results in unnecessary CPU usage when that branch won't execute.
**Action:** Relocated data retrieval steps into the active conditional block when analyzing deepfakes in `media_analyzer.py`.

## 2025-10-25 - [Performance Optimization: IMAP Batch Fetching]

**Learning:** When fetching emails via IMAP, doing so in very small batches (e.g., 10) significantly incurs round-trip overhead and unnecessary rate limit sleep times, blocking for `0.5s` per batch.
**Action:** Increase the `batch_size` to `50` in `src/modules/imap_connection.py`. This significantly minimizes IMAP round-trips and redundant rate-limit sleeps during email retrieval. Avoid checking metadata/sizes (e.g., `RFC822.SIZE`) for *all* unread emails simultaneously without batching, as this risks exceeding IMAP protocol command length limits.

## 2025-02-12 - Case-Insensitive Substring Checking
**Learning:** For simple case-insensitive substring checks, the C-level `in` operator combined with `.lower()` on a string is significantly faster (~20x) than using a pre-compiled regex with `re.IGNORECASE` (e.g., `re.compile("pattern", re.IGNORECASE).search(string)`). The prior code explicitly avoided `.lower()` to save memory allocation overhead on large clean HTML strings, but benchmarking reveals the C-level execution speed of `.lower()` and `in` vastly outweighs the regex engine's overhead.
**Action:** When performing simple case-insensitive substring matches, prefer allocating a lowercased copy of the string and using the `in` operator instead of `re.IGNORECASE` regex searches.
## 2024-06-25 - Optimize Authority Impersonation Domain Matching
**Learning:** In `NLPThreatAnalyzer`, the `_detect_authority_impersonation` function was repeatedly lowercasing authority role match strings (e.g., "CEO") inside nested loops during domain evaluation.
**Action:** Pre-lowercased the strings during extraction inside `_scan_text_patterns` instead of doing it during the nested loop in `_detect_authority_impersonation`. This improves execution speed by ~43% for large match sets.
## 2025-05-25 - Regex Case-Sensitivity Optimization
**Learning:** The regex engine's `re.IGNORECASE` (`re.I`) flag imposes a massive performance overhead in Python (often ~50-100% slower).
**Action:** Instead of compiling regexes with `re.I` for case-insensitive matching, pre-lowercase both the pattern strings (e.g., `[kw.lower() for kw in SPAM_KEYWORDS]`) and the target text (`text.lower()`). This trades a minor memory allocation (string copy) for a massive CPU speedup because the C-level string operations are significantly faster than the complex casing rules inside the Python regex engine.

## 2026-05-26 - Fast Substring Pre-checks for Regex Evaluation
**Learning:** For large collections of regex patterns (like spam keywords), executing `re.search()` is significantly slower (~50x) than pre-checking with Python's C-level `in` operator combined with `any()` and string literals (`any(kw in text.lower() for kw in LITERALS)`).
**Action:** When applying a large compiled regex pattern (e.g. `re.compile("|".join(keywords))`) to text that is unlikely to match in the common case, ALWAYS guard the regex execution with a fast `any(kw in ...)` substring pre-check.
## 2026-05-27 - Remove re.IGNORECASE penalty in NLPAnalyzer
**Learning:** The `re.IGNORECASE` flag imposes a significant runtime penalty (roughly 50-100% overhead) during regex execution in Python. For fast threat scanning, especially on long emails, it's significantly faster to pre-lowercase the text and run a case-sensitive regex when the keywords are already lowercased.
**Action:** When compiling keyword-driven regexes for fast text scanning, explicitly compile with `flags=0` and execute the search against `.lower()` transformed text rather than relying on `re.IGNORECASE`.

## 2026-05-30 - Remove re.IGNORECASE penalty in hidden text regex evaluation
**Learning:** In Python, using `re.IGNORECASE` significantly slows down regex execution. On regexes that don't depend on original casing for correct matching (like HTML tags or simple CSS matches), pre-lowercasing the target string and running a case-sensitive regex is 2-4x faster than using `re.IGNORECASE` on the original string, even accounting for the `.lower()` memory allocation overhead.
**Action:** When a regex with `re.IGNORECASE` is used on strings and the original casing is not needed for the match context, compile the regex without `re.IGNORECASE` and use `.search(text.lower())`.
## 2026-06-01 - Test Loop Execution Break
**Learning:** Testing an infinite `while` loop requires injecting a break condition during the loop execution. This can be cleanly achieved using `unittest.mock.patch` with `side_effect` on an internal function call inside the loop to set the `while` condition variable to `False`.
**Action:** Use a side effect on an internal call like `timer.wait` to safely break out of infinite loops during testing without hanging.
