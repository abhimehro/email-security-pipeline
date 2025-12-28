# Bolt's Journal

## 2024-05-22 - Initial Entry
**Learning:** Performance optimizations should always be measured. Premature optimization is the root of all evil.
**Action:** Always baseline performance before and after making changes.

## 2025-11-09 - Regex Compilation and ML Inference
**Learning:** Sequential `re.findall` on large texts with many patterns is significantly slower than a single pass with a combined regex. Also, legacy code might contain duplicate heavy operations (like ML inference) due to merge conflicts or poor refactoring.
**Action:** Combine regex patterns into single compiled objects with named groups. Audit expensive function calls for redundancy.
## 2024-05-22 - [Repeated Resource Initialization]
**Learning:** Loading static resources (like OpenCV classifiers) inside frequently called methods causes significant I/O overhead.
**Action:** Always check if expensive resources can be initialized once in `__init__` or lazily loaded and cached as instance attributes.
