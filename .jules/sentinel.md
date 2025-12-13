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
