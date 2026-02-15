## 2025-05-23 - Regex Optimization Strategies
**Learning:** Pre-scanning text with a simplified non-capturing regex before running a complex regex with named groups can yield massive speedups (50x+) for the "no match" case, which is the common path in security scanning.
**Action:** When implementing complex pattern matching with many capturing groups, always consider a fast-fail pre-check using a simplified pattern.

## 2025-05-23 - FFT Optimization in OpenCV
**Learning:** `np.fft.fftshift` involves a full array copy and memory allocation. For spectral analysis where only magnitude is needed, masking the corners of the unshifted spectrum is mathematically equivalent to masking the center of the shifted spectrum but avoids the copy, yielding ~1.4x-1.5x speedup.
**Action:** Avoid `fftshift` in real-time video processing pipelines if the operation can be done on unshifted data (e.g. magnitude thresholding).
