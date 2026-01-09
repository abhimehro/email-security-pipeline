## 2025-05-23 - [DoS Prevention in Email Parsing]
**Vulnerability:** Email ingestion was vulnerable to CPU exhaustion (DoS) via excessively large email bodies. Analyzing multi-megabyte text strings with complex regexes in `NLPThreatAnalyzer` caused significant delays (e.g., 26s for 20MB).
**Learning:** Limiting attachment sizes is not enough. The email body itself (text/html) is untrusted input and must be length-limited before processing.
**Prevention:** Implemented `MAX_BODY_SIZE_KB` (default 1MB) in `SystemConfig`. `IMAPClient` now truncates body text and HTML to this limit during parsing, logging a warning when truncation occurs.

## 2025-05-24 - [Unsafe Processing of Disguised Media Files]
**Vulnerability:** The Media Analyzer was processing all files with media extensions (e.g., `.mp4`) through complex libraries like OpenCV/FFmpeg, even if the file content clearly indicated it was a dangerous executable (e.g., MZ header mismatch). This exposed the system to parsing vulnerabilities in dependencies.
**Learning:** File extension checks are insufficient for security decisions. "Defense in Depth" requires skipping risky processing layers if an earlier layer (Magic Byte analysis) has already flagged the input as highly suspicious.
**Prevention:** Updated `MediaAuthenticityAnalyzer.analyze` to skip deepfake detection if `mismatch_score` or `ext_score` indicates a high risk (>= 5.0).
