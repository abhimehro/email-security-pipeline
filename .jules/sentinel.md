## 2025-02-18 - Slack Injection Prevention
**Vulnerability:** Slack alerts were vulnerable to injection/spoofing via unescaped email headers (Subject, Sender).
**Learning:** Slack uses simple characters (&, <, >) for formatting and linking. Unsanitized input allows attackers to create convincing fake links or alter message appearance.
**Prevention:** Always sanitize untrusted input before using it in Slack payloads. Use a dedicated sanitizer that escapes &, <, and >.
