## 2025-05-23 - [DoS Prevention in Email Parsing]
**Vulnerability:** Email ingestion was vulnerable to CPU exhaustion (DoS) via excessively large email bodies. Analyzing multi-megabyte text strings with complex regexes in `NLPThreatAnalyzer` caused significant delays (e.g., 26s for 20MB).
**Learning:** Limiting attachment sizes is not enough. The email body itself (text/html) is untrusted input and must be length-limited before processing.
**Prevention:** Implemented `MAX_BODY_SIZE_KB` (default 1MB) in `SystemConfig`. `IMAPClient` now truncates body text and HTML to this limit during parsing, logging a warning when truncation occurs.

## 2026-01-17 - [DoS Prevention in Headers]
**Vulnerability:** While email bodies were size-limited, email headers (specifically `Subject`) were not. A multi-megabyte subject line could cause excessive memory usage and processing delays in downstream analyzers (Regex/NLP).
**Learning:** Input validation must apply to ALL user-controlled inputs, including headers, not just the main content body. Inconsistent validation boundaries are a common security gap.
**Prevention:** Implemented `MAX_SUBJECT_LENGTH` (1024 chars) in `IMAPClient`. Subjects exceeding this limit are now truncated before further processing.
