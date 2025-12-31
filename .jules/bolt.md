# Bolt's Journal

## 2024-05-22 - Initial Entry
**Learning:** Performance optimizations should always be measured. Premature optimization is the root of all evil.
**Action:** Always baseline performance before and after making changes.

## 2025-11-09 - Regex Compilation and ML Inference
**Learning:** Sequential `re.findall` on large texts with many patterns is significantly slower than a single pass with a combined regex. Also, legacy code might contain duplicate heavy operations (like ML inference) due to merge conflicts or poor refactoring.
**Action:** Combine regex patterns into single compiled objects with named groups. Audit expensive function calls for redundancy.

## 2025-11-14 - OpenCV Loading and Test Data Validity
**Learning:** Repeatedly loading OpenCV classifiers (e.g., `cv2.CascadeClassifier`) inside a loop or frequently called method causes significant I/O overhead. Moving this to `__init__` yields massive speedups (~7.8x in this case). Additionally, discovered that `test_deepfake_detection.py` uses invalid dummy MP4 files (`b'a' * size`), causing `cv2.VideoCapture` to fail silently or with warnings, which made verifying changes tricky until the root cause of test failures was identified as pre-existing.
**Action:** Always check resource loading in hot paths. When tests fail, verify if the test data itself is valid for the library being tested (especially for media files).
