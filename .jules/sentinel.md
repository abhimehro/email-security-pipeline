## 2024-03-24 - [Malware bypass via Content-Disposition omission]

**Vulnerability:** Attackers could bypass the media authenticity analyzer by completely omitting the `Content-Disposition` header or setting it to `inline`, while still providing a malicious `filename` parameter in the `Content-Type` or MIME part.
**Learning:** Checking for the presence of the string "attachment" inside `Content-Disposition` is insufficient for detecting attachments in email parsing. Attackers frequently use non-standard or missing headers to sneak payloads through. Additionally, single-part emails that are themselves malicious files could bypass extraction entirely if not explicitly checked.
**Prevention:** Always verify `part.get_filename()` as a fallback indicator of an attachment. Ensure that single-part email payloads undergo the same attachment detection logic as multi-part emails to prevent complete pipeline evasion.

## 2025-05-18 - [Man-in-the-Middle (MITM) via disabled SSL Verification]
**Vulnerability:** The configuration system allowed setting `verify_ssl=False`, which entirely disabled SSL certificate verification (hostname checking and valid cert enforcement) during IMAP connections. Attackers could intercept and read/modify the emails and credentials in transit if they were on the same network or compromised routing.
**Learning:** Adding a "developer convenience" flag like `verify_ssl=False` into core networking configuration often becomes a permanent fixture in production deployments, negating the value of TLS entirely.
**Prevention:** SSL verification MUST be mandatory. Configuration should not provide the ability to bypass certificate checks for secure connections. Remove bypass logic from all network connection implementations.
