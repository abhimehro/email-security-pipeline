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
