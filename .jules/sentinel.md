## 2024-03-24 - [Path Traversal in Email Attachments]
**Vulnerability:** Path traversal vulnerability in email attachment filename handling. `IMAPClient` accepted raw filenames from email headers, which could contain directory traversal sequences (e.g., `../../etc/passwd`).
**Learning:** `os.path.basename` behavior varies by OS. On Linux, it does not strip Windows-style separators (`\`). Always normalize separators before calling `basename` when handling potentially malicious cross-platform input.
**Prevention:** Implemented strict filename sanitization:
1. Normalize separators (`replace('\\', '/')`)
2. Use `os.path.basename`
3. Whitelist safe characters (alphanumeric, dot, dash, underscore, space)
4. Strip leading dots (hidden files)
