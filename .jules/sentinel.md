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

## 2024-05-18 - Fix TOCTOU vulnerability in file permissions
**Vulnerability:** A Time-of-Check to Time-of-Use (TOCTOU) vulnerability existed when creating the `.env` configuration file in `src/app_runner.py` and `src/utils/setup_wizard.py`. The code used `os.open()` followed by `os.chmod()` on the file path as a fallback. A symbolic link attack could occur in the small time window between creation and permission setting, potentially exposing sensitive credentials to local attackers.
**Learning:** File descriptors (like `fd = os.open(...)`) guarantee that the file operated on is exactly the one created, but fallbacks like `os.chmod(path)` re-resolve the path, opening a window for symbolic link replacement.
**Prevention:** To guarantee permissions atomically at file creation time across all platforms, use `os.umask(0o077)` in a `try/finally` block around the `os.open()` call. This eliminates the need for post-creation permission changes and fundamentally resolves the TOCTOU vulnerability.

## 2025-02-27 - Path Traversal (ZipSlip) in `tarfile` Extraction
**Vulnerability:** The codebase iterated over `.tar` file members and examined their contents without properly validating if the `member.name` contained directory traversal characters (`..`) or absolute paths (leading `/`).
**Learning:** Python's `tarfile` module, when extracted natively (or even when just parsing members manually to check names as in this module), does not inherently sanitize paths prior to Python 3.12 or unless `data_filter` is applied. Even without extracting to disk, exposing traversal-named members without logging sanitization could lead to log injection, and further processing these could lead to unexpected behavior.
**Prevention:** Always validate `member.name` before accessing it: checking for `.startswith("/")` and `".." in name`. Apply `tarfile.data_filter` to the `extraction_filter` attribute if it is available. Also ensure the name is sanitized with `sanitize_for_logging(sanitize_filename(name))` before rendering it to a log file or user interface.
