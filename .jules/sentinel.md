## 2025-05-15 - [Extension Bypass Vulnerability]
**Vulnerability:** File extension checks could be bypassed using trailing whitespace (e.g., 'virus.exe ') because the check used 'endswith' without stripping whitespace.
**Learning:** Python's string methods are precise; Windows filenames are forgiving. Always sanitize filenames before security checks.
**Prevention:** Use .strip() and .replace('\0', '') before checking file extensions.
