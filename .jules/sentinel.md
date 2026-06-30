## 2024-03-24 - [Malware bypass via Content-Disposition omission]

**Vulnerability:** Attackers could bypass the media authenticity analyzer by completely omitting the `Content-Disposition` header or setting it to `inline`, while still providing a malicious `filename` parameter in the `Content-Type` or MIME part.
**Learning:** Checking for the presence of the string "attachment" inside `Content-Disposition` is insufficient for detecting attachments in email parsing. Attackers frequently use non-standard or missing headers to sneak payloads through. Additionally, single-part emails that are themselves malicious files could bypass extraction entirely if not explicitly checked.
**Prevention:** Always verify `part.get_filename()` as a fallback indicator of an attachment. Ensure that single-part email payloads undergo the same attachment detection logic as multi-part emails to prevent complete pipeline evasion.

## 2025-05-18 - [Man-in-the-Middle (MITM) via disabled SSL Verification]
**Vulnerability:** The configuration system allowed setting `verify_ssl=False`, which entirely disabled SSL certificate verification (hostname checking and valid cert enforcement) during IMAP connections. Attackers could intercept and read/modify the emails and credentials in transit if they were on the same network or compromised routing.
**Learning:** Adding a "developer convenience" flag like `verify_ssl=False` into core networking configuration often becomes a permanent fixture in production deployments, negating the value of TLS entirely.
**Prevention:** SSL verification MUST be mandatory. Configuration should not provide the ability to bypass certificate checks for secure connections. Remove bypass logic from all network connection implementations.

## 2025-05-18 - [Insecure Deserialization in ML Models]
**Vulnerability:** Hugging Face models and tokenizers were being loaded via `from_pretrained` without enforcing safe serialization formats. This could allow insecure deserialization (Pickle arbitrary code execution) if malicious model weights are fetched or substituted.
**Learning:** The default behavior of `from_pretrained` might fall back to loading unsafe Pickle files if `use_safetensors=True` is not explicitly set, exposing the application to RCE (Remote Code Execution) through supply-chain attacks or compromised model repositories.
**Prevention:** Always set `use_safetensors=True` when loading models and tokenizers using Hugging Face `transformers` to enforce the use of the secure `safetensors` format.
## 2026-04-23 - Prevent symlink attacks with O_NOFOLLOW in os.open
**Vulnerability:** os.open calls used to create config files lacked the O_NOFOLLOW flag, potentially allowing an attacker to overwrite sensitive files by creating a symlink.
**Learning:** Always use os.O_NOFOLLOW (or its cross-platform equivalent getattr(os, "O_NOFOLLOW", 0)) when opening or creating sensitive files to mitigate TOCTOU symlink vulnerabilities.
**Prevention:** Apply O_NOFOLLOW in os.open flags for any file creation/open operations that might be targeted by symlink attacks.

## 2026-05-02 - Explicit TLS Verification Required for `requests`
**Vulnerability:** Default `requests.post()` calls without explicit `verify=True`, which is flagged by linters and security policies despite `requests` verifying TLS by default.
**Learning:** Security policies in this codebase mandate explicit `verify=True` for all `requests` network calls to ensure TLS verification cannot be accidentally bypassed by environment configurations.
**Prevention:** Always include `verify=True` when adding new network requests using the `requests` library.
## 2026-05-10 - Fix password logging in setup wizard and refactor complex method
**Vulnerability:** The exception message in `_test_connection` printed clear text, logging the password if present in the IMAP error.
**Learning:** Hardcoded ANSI escape codes in f-strings were fixed along with the complex code structure in `_get_credentials`. Always ensure passwords and sensitive data are sanitized from generic exception logs.
**Prevention:** Mask passwords explicitly in the `try-except` block before output. Refactor overly complex input loops into separate helper functions.
## 2026-05-10 - Fix False Positive CodeQL alerts
**Learning:** CodeQL will flag variables that simply have `PASSWORD` in their name, even if they only contain static UI text strings (like `OUTLOOK_APP_PASSWORD_TIP`).
**Prevention:** Avoid using words like "password" in variable names that don't actually hold secrets to prevent false positives in security scanning tools.
## 2026-05-24 - Fix `re.error` vulnerabilities in regex replacements
**Vulnerability:** `re.sub()` was used with dynamically generated strings (app secrets, emails) as the replacement. When the string contains backslash sequences (e.g. `\1`), `re.sub` parses them as backreferences causing `re.error` or mis-substitution, leading to config corruption.
**Learning:** Returning a string from a callable in `re.sub` prevents backreference parsing. A dedicated function was previously used, but it's cleaner and avoids static analysis issues to use lambdas (`lambda _: f"literal"`). Python's `re.sub` replacement string acts as a template by default, not a literal string.
**Prevention:** When using `re.sub()` with user-controlled or dynamically generated strings for replacement, always wrap the replacement in a lambda expression (e.g. `lambda _: replacement_string`) rather than passing the string directly or using a named function.
## 2026-06-01 - Fix tarfile Zip Slip path traversal vulnerability
**Vulnerability:** Zip Slip / path traversal in `tarfile` parsing. Iterating over `tarfile.open()` allows a crafted archive to supply malicious `member.name` properties (like `../../etc/passwd`). Calling `extractfile(member)` blindly on those members creates an extraction vulnerability.
**Learning:** Python's `tarfile` module does not intrinsically protect against path traversal when looping `for member in tf:` or using `extractfile(member)`.
**Prevention:** Apply the PEP-706 extraction filter natively (`tf.extraction_filter = getattr(tarfile, "data_filter", ...)`) AND explicitly guard `member.name.startswith("/")` and `".." in member.name` during parsing iteration.
## 2024-06-09 - Path Traversal Log Leakage
**Vulnerability:** Path Traversal Log Leakage
**Learning:** During analysis, path traversal checks logged the raw malicious paths in the analyzer warning.
**Prevention:** Sanitize the raw malicious strings before adding them to warning lists and subsequently to the logger.
## 2024-06-09 - CodeScene Complex Method Hotspot
**Vulnerability:** CodeScene flagged `_inspect_zip_contents` as a Complex Method due to the added path traversal check logic.
**Learning:** Adding new checks to existing loops inside complex methods can trigger CodeScene "Complex Method" hotspot warnings, breaking CI checks.
**Prevention:** Extract complex nested logic or multiple conditional checks into separate helper methods to keep the cyclomatic complexity of individual functions low.
## 2025-11-08 - Use parsed.hostname over parsed.netloc for Webhook Security Checks
**Vulnerability:** A logic flaw in `src/modules/alert_system.py` and `src/utils/config.py` used `parsed.netloc.lower() == "hooks.slack.com"` for webhook redaction and SSRF validation. `netloc` includes explicit ports and user credentials. An attacker could craft a webhook URL like `https://hooks.slack.com:443/services/...` to bypass these checks.
**Learning:** `urllib.parse.urlparse().netloc` returns the entire authority component (credentials + domain + port). Using it for exact domain matching enables bypasses when ports or user info are added. Furthermore, `netloc` is not reliably lowercased for unknown or uppercase protocols.
**Prevention:** Always use `(urlparse(url).hostname or "").lower()` when verifying or matching domains for security constraints, as `.hostname` extracts only the domain name component safely without credentials or ports.
