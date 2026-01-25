## 2025-05-23 - [DoS Prevention in Email Parsing]
**Vulnerability:** Email ingestion was vulnerable to CPU exhaustion (DoS) via excessively large email bodies. Analyzing multi-megabyte text strings with complex regexes in `NLPThreatAnalyzer` caused significant delays (e.g., 26s for 20MB).
**Learning:** Limiting attachment sizes is not enough. The email body itself (text/html) is untrusted input and must be length-limited before processing.
**Prevention:** Implemented `MAX_BODY_SIZE_KB` (default 1MB) in `SystemConfig`. `IMAPClient` now truncates body text and HTML to this limit during parsing, logging a warning when truncation occurs.

## 2025-05-24 - [Header Injection/Bypass in Email Parsing]
**Vulnerability:** `EmailData` stored headers as a simple dictionary `Dict[str, str]`, causing duplicate headers (like `Received`, `Received-SPF`, `DKIM-Signature`, `From`) to be overwritten. This allowed attackers to bypass security checks (e.g., hop count limit, SPF validation) by injecting fake headers that overwrote legitimate ones.
**Learning:** RFC 5322 allows multiple headers of the same name. Storing them in a dictionary where keys are unique results in data loss and potential security bypasses.
**Prevention:** Updated `EmailData` to `Dict[str, Union[str, List[str]]]` and modified `IMAPClient` to collect all values. Updated `SpamAnalyzer` to validate against all occurrences of critical headers.

## 2026-01-17 - [DoS Prevention in Headers]
**Vulnerability:** While email bodies were size-limited, email headers (specifically `Subject`) were not. A multi-megabyte subject line could cause excessive memory usage and processing delays in downstream analyzers (Regex/NLP).
**Learning:** Input validation must apply to ALL user-controlled inputs, including headers, not just the main content body. Inconsistent validation boundaries are a common security gap.
**Prevention:** Implemented `MAX_SUBJECT_LENGTH` (1024 chars) in `IMAPClient`. Subjects exceeding this limit are now truncated before further processing.

## 2026-02-13 - [Media Processing Exploit Prevention]
**Vulnerability:** `MediaAuthenticityAnalyzer` passed files with valid extensions (e.g., `.mp4`) to `cv2.VideoCapture` without verifying their content type (magic bytes). This could allow attackers to trigger vulnerabilities in the underlying media libraries (ffmpeg/OpenCV) using malformed or disguised files.
**Learning:** File extensions are user-controlled and untrustworthy. Detection logic must default to "Fail Closed": if a file claims to be a specific type but its signature cannot be verified, it should be treated as high-risk, not processed blindly.
**Prevention:** Implemented strict magic byte verification for media files in `MediaAuthenticityAnalyzer`. Files with media extensions but missing/invalid signatures now trigger a critical threat score and bypass deepfake processing.

## 2026-05-21 - [DoS Prevention in IMAP Fetch]
**Vulnerability:** `IMAPClient` fetched full email content (`RFC822`) before checking its size, exposing the system to memory exhaustion (OOM) and bandwidth DoS if a malicious actor sent a massive email (e.g., 1GB+). Previous truncations only happened *after* the data was loaded into memory.
**Learning:** Ingestion pipelines must validate data size *before* retrieving the full payload. "Check-then-act" is crucial for resource protection in network protocols.
**Prevention:** Modified `IMAPClient` to fetch `(RFC822.SIZE)` metadata first. Emails exceeding the configured limit are skipped entirely, preventing them from ever consuming system memory.

## 2026-06-15 - [Authentication-Results Verification Bypass]
**Vulnerability:** `SpamAnalyzer` checked for the *existence* of DKIM signatures but failed to verify their validity status (e.g., `dkim=fail`) in the `Authentication-Results` header. This allowed attackers to bypass authentication checks by including a fake or invalid signature.
**Learning:** Checking for the presence of a security control (like a signature) is insufficient. You must verify the *outcome* of that control. Upstream validation results (like `Authentication-Results`) are the source of truth for email authenticity.
**Prevention:** Updated `SpamAnalyzer` to parse `Authentication-Results` headers and penalize emails with explicit `dkim=fail` or `spf=fail` statuses, regardless of signature presence.
