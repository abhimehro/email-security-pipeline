## 2024-05-23 - [Insecure Temp File Handling in Media Analysis]
**Vulnerability:** `MediaAuthenticityAnalyzer` was using `tempfile.NamedTemporaryFile(delete=False)` to create files in the shared system temp directory, relying on a `finally` block for cleanup. This posed risks of resource leaks (DoS) on crashes and potential TOCTOU/permissions issues.
**Learning:** `tempfile.NamedTemporaryFile(delete=False)` is risky because cleanup isn't guaranteed on hard crashes. Also, files in shared temp dirs can be exposed if permissions aren't tight.
**Prevention:** Use `tempfile.TemporaryDirectory()` as a context manager. It handles cleanup robustly (even on exceptions) and creates a directory with restricted permissions (700 on POSIX), isolating the temp files from other users.
