## 2025-02-17 - [Log Injection Fix]
**Vulnerability:** Untrusted email headers (Subject, Sender, Recipient) were printed directly to the console in AlertSystem. This allowed attackers to use newlines to spoof log entries or ANSI escape codes to manipulate the terminal.
**Learning:** Console logs are an often-overlooked injection vector. Simple print statements trust the input format.
**Prevention:** Always sanitize untrusted input before logging. For console output, stripping control characters and normalizing whitespace is effective.
