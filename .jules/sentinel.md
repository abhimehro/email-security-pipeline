## 2025-02-18 - Slack Injection Prevention
**Vulnerability:** Slack alerts were vulnerable to injection/spoofing via unescaped email headers (Subject, Sender).
**Learning:** Slack uses simple characters (&, <, >) for formatting and linking. Unsanitized input allows attackers to create convincing fake links or alter message appearance.
**Prevention:** Always sanitize untrusted input before using it in Slack payloads. Use a dedicated sanitizer that escapes &, <, and >.
## 2025-05-15 - [Extension Bypass Vulnerability]
**Vulnerability:** File extension checks could be bypassed using trailing whitespace (e.g., 'virus.exe ') because the check used 'endswith' without stripping whitespace.
**Learning:** Python's string methods are precise; Windows filenames are forgiving. Always sanitize filenames before security checks.
**Prevention:** Use .strip() and .replace('\0', '') before checking file extensions.
# Sentinel Journal

## 2025-02-17 - [Log Injection & Terminal Manipulation Mitigation]
**Vulnerability:** User-controlled data (email subjects, senders) was being logged directly to files and console without sanitization. This allowed for Log Injection (CRLF) attacks and potential terminal manipulation via ANSI escape codes.
**Learning:** Even internal logging systems can be attack vectors if they process untrusted input. Standard Python logging does not automatically sanitize all control characters.
**Prevention:** Implemented a centralized `sanitize_for_logging` utility that:
1. Escapes newlines (`\n`, `\r`).
2. Strips ANSI escape codes.
3. Normalizes Unicode.
4. Truncates long inputs.
This pattern should be applied to ALL user inputs before they touch logs or the console.
## 2025-02-17 - [Log Injection Fix]
**Vulnerability:** Untrusted email headers (Subject, Sender, Recipient) were printed directly to the console in AlertSystem. This allowed attackers to use newlines to spoof log entries or ANSI escape codes to manipulate the terminal.
**Learning:** Console logs are an often-overlooked injection vector. Simple print statements trust the input format.
**Prevention:** Always sanitize untrusted input before logging. For console output, stripping control characters and normalizing whitespace is effective.

## 2025-05-21 - [DoS Prevention in Email Ingestion]
**Vulnerability:** Email ingestion was vulnerable to resource exhaustion (DoS) via "zip bomb" style attacks or excessive attachments, as there were no limits on the total number or size of attachments per email.
**Learning:** Processing external input (emails) requires strict limits on all dimensions (count, size, depth) to prevent resource exhaustion.
**Prevention:** Implemented strict limits on total attachment count and total attachment size per email in `IMAPClient`.
