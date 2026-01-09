## 2025-05-23 - [DoS Prevention in Email Parsing]
**Vulnerability:** Email ingestion was vulnerable to CPU exhaustion (DoS) via excessively large email bodies. Analyzing multi-megabyte text strings with complex regexes in `NLPThreatAnalyzer` caused significant delays (e.g., 26s for 20MB).
**Learning:** Limiting attachment sizes is not enough. The email body itself (text/html) is untrusted input and must be length-limited before processing.
**Prevention:** Implemented `MAX_BODY_SIZE_KB` (default 1MB) in `SystemConfig`. `IMAPClient` now truncates body text and HTML to this limit during parsing, logging a warning when truncation occurs.
## 2025-01-01 - ReDoS in Spam Analyzer
**Vulnerability:** Regular Expression Denial of Service (ReDoS) in `src/modules/spam_analyzer.py`.
**Learning:** The regex `color:\s*#fff.*background.*#fff` used greedy quantifiers (`.*`) multiple times, allowing catastrophic backtracking ((N^2)$) when inputs matched the start but failed later.
**Prevention:** Use bounded quantifiers (e.g., `.{0,100}`) instead of `.*` when matching content between two known markers, especially in untrusted input like email bodies.
