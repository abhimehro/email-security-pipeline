## 2024-03-24 - [Malware bypass via Content-Disposition omission]

**Vulnerability:** Attackers could bypass the media authenticity analyzer by completely omitting the `Content-Disposition` header or setting it to `inline`, while still providing a malicious `filename` parameter in the `Content-Type` or MIME part.
**Learning:** Checking for the presence of the string "attachment" inside `Content-Disposition` is insufficient for detecting attachments in email parsing. Attackers frequently use non-standard or missing headers to sneak payloads through. Additionally, single-part emails that are themselves malicious files could bypass extraction entirely if not explicitly checked.
**Prevention:** Always verify `part.get_filename()` as a fallback indicator of an attachment. Ensure that single-part email payloads undergo the same attachment detection logic as multi-part emails to prevent complete pipeline evasion.

## 2024-04-03 - [Cross-Platform Compatibility for File Permission Hardening]
**Vulnerability:** When using `os.fchmod` to enforce file permissions (e.g., to prevent TOCTOU vulnerabilities), the function call might fail on certain environments (such as Windows) by raising an `OSError` or `NotImplementedError`, instead of an `AttributeError`, leaving the file with default (potentially unsafe) permissions or causing the application to crash.
**Learning:** `os.fchmod` might exist in the `os` module on Windows, causing `hasattr(os, "fchmod")` to return True or bypassing the `AttributeError` catch block, but it will raise other exceptions (`OSError` or `NotImplementedError`) when called on a standard file descriptor.
**Prevention:** Always wrap `os.fchmod` calls in a broader `try...except (AttributeError, OSError, NotImplementedError):` block and provide a fallback to `os.chmod` to ensure cross-platform compatibility while maintaining restrictive permissions.
