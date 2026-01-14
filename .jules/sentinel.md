## 2025-05-23 - [DoS Prevention in Email Parsing]
**Vulnerability:** Email ingestion was vulnerable to CPU exhaustion (DoS) via excessively large email bodies. Analyzing multi-megabyte text strings with complex regexes in `NLPThreatAnalyzer` caused significant delays (e.g., 26s for 20MB).
**Learning:** Limiting attachment sizes is not enough. The email body itself (text/html) is untrusted input and must be length-limited before processing.
**Prevention:** Implemented `MAX_BODY_SIZE_KB` (default 1MB) in `SystemConfig`. `IMAPClient` now truncates body text and HTML to this limit during parsing, logging a warning when truncation occurs.

## 2025-11-09 - [Log Injection in Email Ingestion]
**Vulnerability:** `IMAPClient` in `email_ingestion.py` logged untrusted input (folder names, email attachment filenames) directly using `logging` calls. This allowed Log Injection (CWE-117) via malicious folder names or attachment filenames containing newlines/ANSI codes.
**Learning:** Even internal-looking data like "folder names" can be manipulated if the source (IMAP server) is compromised or if configuration is tampered with. Email headers (filenames) are definitely untrusted user input.
**Prevention:** Imported and applied `sanitize_for_logging` to all untrusted variables (`folder`, `filename`, `email_id`) before passing them to the logger. Added regression test `tests/test_email_ingestion_security.py`.
