## 2025-05-23 - Regex Optimization Strategies
**Learning:** Pre-scanning text with a simplified non-capturing regex before running a complex regex with named groups can yield massive speedups (50x+) for the "no match" case, which is the common path in security scanning.
**Action:** When implementing complex pattern matching with many capturing groups, always consider a fast-fail pre-check using a simplified pattern.

## 2024-05-22 - Initial Entry
**Learning:** Performance optimizations should always be measured. Premature optimization is the root of all evil.
**Action:** Always baseline performance before and after making changes.

## 2025-05-15 - Regex Compilation and Import Overhead
**Learning:** Pre-compiling regexes in Python's `re` module offers modest gains (~9% in this case), but the real win is code clarity and avoiding hidden overheads like repeated `import` statements inside hot loops.
**Action:** Always hoist imports and regex compilations to module or class scope for frequently called methods.

## 2025-11-09 - Regex Compilation and ML Inference
**Learning:** Sequential `re.findall` on large texts with many patterns is significantly slower than a single pass with a combined regex. Also, legacy code might contain duplicate heavy operations (like ML inference) due to merge conflicts or poor refactoring.
**Action:** Combine regex patterns into single compiled objects with named groups. Audit expensive function calls for redundancy.

## 2025-11-13 - Regex Optimization Strategy
**Learning:** When matching multiple patterns where identification of the specific match is required, a hybrid approach works best for moderate pattern counts. Use a simple combined OR regex (no capturing groups) for a fast "check" pass. If it matches, use a complex combined regex with named groups for identification. This avoids the overhead of named groups in the common "no match" case and is faster than iterating individual regexes in the "match" case.
**Action:** Use `SIMPLE_PATTERN.search()` for detection and `COMPLEX_PATTERN.finditer()` for identification when optimizing multi-pattern matching.

## 2025-11-14 - LRU Cache on Large Inputs
**Learning:** Applying `lru_cache` to functions taking potentially large unique strings (like email bodies) creates significant memory and CPU overhead (hashing). If the consumer (e.g., a Transformer model) only processes a prefix (e.g., 512 tokens), truncating the input *before* caching provides massive speedups (~300x in benchmarks) and effective cache utilization.
**Action:** Truncate large input strings to the effective processing limit before passing them to cached functions.

## 2026-02-08 - Memory-Efficient Match Counting
**Learning:** `re.findall()` allocates a list of all matching strings, which wastes memory when only the count is needed. For large texts (up to 1MB) with many matches, `sum(1 for _ in re.finditer())` achieves >99% memory reduction while maintaining comparable speed.
**Action:** Use `re.finditer()` with a generator expression instead of `re.findall()` when only the match count is needed.

## 2026-02-14 - OpenCV DFT vs Numpy FFT
**Learning:** For frequency domain analysis of images (like deepfake compression artifacts), `cv2.dft` is approximately 2x faster than `np.fft.fft2`. Additionally, sampling a subset of frames (e.g., 5) instead of processing all (e.g., 20) for statistical artifacts provides massive speedups (5.8x total reduction) without compromising detection accuracy for persistent patterns.
**Action:** Prefer `cv2.dft` over `np.fft` for image analysis and use statistical sampling for frame-based video analysis.

## 2026-03-01 - Avoid Large String Concatenation
**Learning:** Large string concatenation (e.g., combining 1MB+ strings) allocates new memory and triggers copying, which is expensive in hot paths. Processing parts sequentially avoids this allocation.
**Action:** Process large text fields individually when extracting data (e.g., regex matching) instead of concatenating them.

## 2026-03-05 - Multipart Email Parsing Efficiency
**Learning:** String concatenation in a loop (`body += part`) for potentially many parts leads to O(N^2) complexity, which can be a DoS vector for large emails with many small parts. Using `list.append()` followed by `"".join()` is O(N) and significantly safer and faster for large inputs.
**Action:** Use list accumulation for string building in loops, especially when handling external input like email bodies.

## 2026-03-08 - ThreadPoolExecutor Creation Overhead
**Learning:** In one benchmark, creating a `ThreadPoolExecutor` inside a loop (or per item in a batch) added ~340us of overhead per attachment, with total per-item overhead around 422us compared to reusing a shared executor (~0us incremental cost). Reusing a single executor instance is critical, especially for short-lived tasks.
**Action:** Move `ThreadPoolExecutor` initialization to `__init__` or module level and reuse it across calls.
## 2025-05-23 - FFT Optimization in OpenCV
**Learning:** `np.fft.fftshift` involves a full array copy and memory allocation. For spectral analysis where only magnitude is needed, masking the corners of the unshifted spectrum is mathematically equivalent to masking the center of the shifted spectrum but avoids the copy, yielding ~1.4x-1.5x speedup.
**Action:** Avoid `fftshift` in real-time video processing pipelines if the operation can be done on unshifted data (e.g. magnitude thresholding).

## 2026-03-09 - Redundant URL Processing in Spam Analysis
**Learning:** Parsing URLs with `urllib.parse` is relatively expensive (O(N) for N characters). When analyzing emails with many duplicate URLs (e.g., signatures, tracking pixels), redundant parsing causes significant performance overhead (18x-32x slower).
**Action:** Use a local cache (e.g., `dict`) to store parsing/analysis results for unique items when iterating over potentially large collections with duplicates.

## 2026-03-10 - Media Analysis Frame Sampling
**Learning:** Facial analysis using `detectMultiScale` is computationally expensive and linear with the number of frames. Analyzing a statistical sample of frames (e.g., 5) instead of all extracted frames (e.g., 10) provides a 50% speedup while still catching persistent inconsistencies.
**Action:** Use frame subsampling for expensive per-frame operations like face detection, similar to how it's done for compression artifacts.

## 2026-03-11 - Caching Instance Methods and Memory Leaks
**Learning:** Using `@lru_cache` on an instance method creates a strong reference to `self` in the cache key. If the instance is short-lived or recreated frequently, this causes a memory leak and ineffective caching (0% hit rate). Refactoring to a `@staticmethod` or module-level function solves this by removing `self` from the cache key.
**Action:** Always use `@staticmethod` or standalone functions when caching logic that doesn't strictly depend on instance state.
