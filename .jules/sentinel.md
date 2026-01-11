## 2025-05-23 - [DoS Prevention in Email Parsing]
**Vulnerability:** Email ingestion was vulnerable to CPU exhaustion (DoS) via excessively large email bodies. Analyzing multi-megabyte text strings with complex regexes in `NLPThreatAnalyzer` caused significant delays (e.g., 26s for 20MB).
**Learning:** Limiting attachment sizes is not enough. The email body itself (text/html) is untrusted input and must be length-limited before processing.
**Prevention:** Implemented `MAX_BODY_SIZE_KB` (default 1MB) in `SystemConfig`. `IMAPClient` now truncates body text and HTML to this limit during parsing, logging a warning when truncation occurs.

## 2025-05-23 - [ReDoS in Spam Analysis]
**Vulnerability:** The regex `color:\s*#fff.*background.*#fff` in `SpamAnalyzer` was vulnerable to catastrophic backtracking (ReDoS). A crafted email with a large payload (e.g. 50k chars) triggering the pattern could freeze the worker for seconds or minutes.
**Learning:** Unbounded wildcards (`.*`) in regexes running on untrusted input are dangerous, especially when combined with alternations or other wildcards.
**Prevention:** Replaced unbounded `.*` with bounded `.{0,100}` to limit the search scope, effectively mitigating the ReDoS risk while preserving detection capability for typical cases.
