## 2025-05-15 - PII Leakage in Logs
**Vulnerability:** Email addresses were being logged in plain text in `IMAPClient` and `IMAPConnection` modules.
**Learning:** Application logs often inadvertently capture sensitive data during connection establishment or error reporting. Developers should sanitize inputs specifically for logging.
**Prevention:** Use a dedicated `redact_email` or `sanitize_pii` function in logging calls, especially for configuration values like `email`, `username`, or `api_key`.
