## 2025-05-23 - [DoS Prevention in Email Parsing]
**Vulnerability:** Email ingestion was vulnerable to CPU exhaustion (DoS) via excessively large email bodies. Analyzing multi-megabyte text strings with complex regexes in `NLPThreatAnalyzer` caused significant delays (e.g., 26s for 20MB).
**Learning:** Limiting attachment sizes is not enough. The email body itself (text/html) is untrusted input and must be length-limited before processing.
**Prevention:** Implemented `MAX_BODY_SIZE_KB` (default 1MB) in `SystemConfig`. `IMAPClient` now truncates body text and HTML to this limit during parsing, logging a warning when truncation occurs.

## 2025-05-24 - [Header Injection/Bypass in Email Parsing]
**Vulnerability:** `EmailData` stored headers as a simple dictionary `Dict[str, str]`, causing duplicate headers (like `Received`, `Received-SPF`, `DKIM-Signature`, `From`) to be overwritten. This allowed attackers to bypass security checks (e.g., hop count limit, SPF validation) by injecting fake headers that overwrote legitimate ones.
**Learning:** RFC 5322 allows multiple headers of the same name. Storing them in a dictionary where keys are unique results in data loss and potential security bypasses.
**Prevention:** Updated `EmailData` to `Dict[str, Union[str, List[str]]]` and modified `IMAPClient` to collect all values. Updated `SpamAnalyzer` to validate against all occurrences of critical headers.
