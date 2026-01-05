# Bolt's Journal

## 2024-05-22 - Initial Entry
**Learning:** Performance optimizations should always be measured. Premature optimization is the root of all evil.
**Action:** Always baseline performance before and after making changes.

## 2025-11-09 - Regex Compilation and ML Inference
**Learning:** Sequential `re.findall` on large texts with many patterns is significantly slower than a single pass with a combined regex. Also, legacy code might contain duplicate heavy operations (like ML inference) due to merge conflicts or poor refactoring.
**Action:** Combine regex patterns into single compiled objects with named groups. Audit expensive function calls for redundancy.

## 2024-05-22 - Caching OpenCV CascadeClassifier
**Learning:** Loading `cv2.CascadeClassifier` is a surprisingly expensive operation (involving file I/O and XML parsing) that can significantly impact performance if done repeatedly in a loop.
**Action:** Always cache or lazily load `cv2.CascadeClassifier` (and similar heavy resources) in the `__init__` method or a class-level variable instead of loading it inside the processing method.
