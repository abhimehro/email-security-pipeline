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

## 2026-05-25 - [Sensitive Data Exposure in Log Objects]
**Vulnerability:** `EmailAccountConfig` and `AnalysisConfig` dataclasses included sensitive fields (`app_password`, `deepfake_api_key`) in their default `__repr__` method. This caused credentials to be leaked in plain text if these objects were ever logged for debugging (e.g., `logger.info(config)`).
**Learning:** Python `dataclass` automatically generates a `__repr__` that includes all fields by default. Developers must explicitly exclude sensitive fields using `field(repr=False)` to prevent accidental leakage in logs.
**Prevention:** Updated `EmailAccountConfig` and `AnalysisConfig` to use `field(repr=False)` for all sensitive fields. Added regression tests in `tests/test_config_security.py` to verify that `str(config)` does not contain secrets.

## 2026-06-15 - [Authentication-Results Verification Bypass]
**Vulnerability:** `SpamAnalyzer` checked for the *existence* of DKIM signatures but failed to verify their validity status (e.g., `dkim=fail`) in the `Authentication-Results` header. This allowed attackers to bypass authentication checks by including a fake or invalid signature.
**Learning:** Checking for the presence of a security control (like a signature) is insufficient. You must verify the *outcome* of that control. Upstream validation results (like `Authentication-Results`) are the source of truth for email authenticity.
**Prevention:** Updated `SpamAnalyzer` to parse `Authentication-Results` headers and penalize emails with explicit `dkim=fail` or `spf=fail` statuses, regardless of signature presence.

## 2026-06-16 - [Resource Leak in Temp File Handling]
**Vulnerability:** `MediaAuthenticityAnalyzer` created temporary files for OpenCV processing but failed to clean them up if an exception occurred during the `write` operation (e.g., disk full). This could lead to disk exhaustion (DoS).
**Learning:** `tempfile.NamedTemporaryFile(delete=False)` requires manual cleanup in ALL exit paths. Standard `try...finally` blocks must encompass the file creation and writing steps to ensure `os.unlink` is always called.
**Prevention:** Refactored `_check_deepfake_indicators` to wrap file creation, writing, and usage in a single `try...finally` block, ensuring deterministic cleanup.

## 2026-02-08 - [Credential Leakage in setup.sh]
**Vulnerability:** `setup.sh` passed credentials as command-line arguments to `sed`, exposing them via `ps aux`. Passwords with special characters (e.g., `|`) could also cause command injection or breakage.
**Learning:** Never pass secrets as command-line arguments. Use environment variables (not visible in process listings) and a robust language like Python for file manipulation instead of `sed`.
**Prevention:** Replaced `sed` with an inline Python script. Secrets are passed as one-off environment variables to `python3`, never exported to the shell. Dead `SED_CMD` detection code was removed.

## 2026-06-25 - [Media Analysis Validation Gap]
**Vulnerability:** The deepfake detection module processed files based on their extension (e.g., `.mov`) even if they failed strict signature validation. This could allow attackers to bypass validation and trigger vulnerabilities in underlying media libraries (like OpenCV) by disguising malicious files with allowed extensions.
**Learning:** Inconsistent validation logic (checking some extensions strictly but not others) creates security gaps. All inputs processed by complex parsers must be strictly validated against a known-good allowlist of signatures.
**Prevention:** Updated `MediaAuthenticityAnalyzer` to enforce strict magic byte validation for all supported media extensions, preventing processing of any file that does not match a known secure signature.

## 2026-06-26 - [File Extension Check Bypass]
**Vulnerability:** File extension checks could be bypassed by appending a trailing dot (e.g., `malware.exe.`).
**Learning:** Windows treats files with trailing dots as the file without the dot (e.g., `malware.exe.` executes as `malware.exe`), but exact-match extension checks often fail.
**Prevention:** Always strip trailing dots from filenames before validation and processing, especially when dealing with cross-platform file handling.

## 2026-06-27 - [DoS via MIME Bomb]
**Vulnerability:** Email ingestion was vulnerable to DoS via "MIME bombs" (emails with an excessive number of parts). Iterating over thousands of MIME parts in `parse_email` consumed excessive CPU and memory, even if individual parts were small.
**Learning:** Limiting data size is not enough; the complexity of the data structure (e.g., nesting depth, number of elements) must also be bounded.
**Prevention:** Implemented `MAX_MIME_PARTS` limit (100) in `IMAPClient.parse_email`. Processing halts and remaining parts are truncated if the limit is exceeded.

## 2026-06-29 - [Unicode Spoofing in Alerts]
**Vulnerability:** The alert system's text sanitization logic (`_sanitize_text`) only filtered ASCII control characters (0-31, 127-159), allowing dangerous Unicode characters like Right-to-Left Override (U+202E) to pass through. This enabled attackers to spoof file extensions in console logs and Slack alerts (e.g., making `evil[RTLO]fdp.exe` appear as `evilexe.pdf`), potentially tricking administrators.
**Learning:** Naive ASCII-based sanitization is insufficient in a Unicode world. Security controls must explicitly handle or filter invisible, formatting, and control characters from all Unicode categories (Cc, Cf, etc.) to prevent UI redressing and confusion attacks.
**Prevention:** Updated `AlertSystem` to use `unicodedata` and `str.isprintable()` to strictly filter out non-printable characters and format controls (Category Cf) from all alert outputs, while preserving legitimate international text.
## 2025-02-23 - [Information Leakage in Logs]
**Vulnerability:** Slack and Discord webhook URLs contain secrets (tokens) in their path, which leak into logs when request exceptions occur.
**Learning:** Sanitizing query parameters is insufficient for APIs that use path-based secrets. Exception messages from `requests` often include the full URL.
**Prevention:** Sanitize exception messages by redacting known sensitive URL patterns (both query params and paths) before logging.
