# Bolt's Journal

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

## 2026-03-05 - Multipart Email Parsing Efficiency
**Learning:** String concatenation in a loop (`body += part`) for potentially many parts leads to O(N^2) complexity, which can be a DoS vector for large emails with many small parts. Using `list.append()` followed by `"".join()` is O(N) and significantly safer and faster for large inputs. Additionally, size limits must be enforced at the byte level (before decoding) to accurately respect configured limits and avoid decoding unnecessarily large payloads.
**Action:** Use list accumulation for string building in loops, especially when handling external input like email bodies. Truncate raw bytes before decoding to avoid wasting CPU/memory on content that will be discarded.
