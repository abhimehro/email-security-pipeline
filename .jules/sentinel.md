## 2025-05-15 - PII Leakage in Logs
**Vulnerability:** Email addresses were being logged in plain text in `IMAPClient` and `IMAPConnection` modules.
**Learning:** Application logs often inadvertently capture sensitive data during connection establishment or error reporting. Developers should sanitize inputs specifically for logging.
**Prevention:** Use a dedicated `redact_email` or `sanitize_pii` function in logging calls, especially for configuration values like `email`, `username`, or `api_key`.

---

## 2025-05-23 - Weak Password Reset Tokens
**Vulnerability:** Password reset tokens were generated using a predictable pattern based on user ID and timestamp, making them susceptible to guessing and token replay.
**Learning:** Security tokens must be generated using cryptographically secure random functions and should not encode easily guessable user information.
**Prevention:** Use a CSPRNG-backed token generator (e.g., `crypto.randomBytes` or equivalent) with sufficient entropy, and enforce single-use, short-lived reset tokens stored as hashed values server-side.

## 2025-07-02 - Insecure Direct Object Reference (IDOR) in Message Threads
**Vulnerability:** Users could access message threads belonging to other accounts by manipulating the `thread_id` in the URL, due to missing ownership checks.
**Learning:** Never trust client-supplied identifiers for authorization; every access to a resource must be checked against the authenticated principal.
**Prevention:** Implement server-side authorization checks tying `thread_id` (and similar identifiers) to the authenticated user, and use opaque, non-sequential identifiers where practical.

## 2025-09-18 - Unvalidated Redirects After Login
**Vulnerability:** The `return_to` query parameter allowed redirection to arbitrary external domains after login, enabling phishing and open-redirect abuse.
**Learning:** Post-authentication redirects are a prime target for attackers to chain into phishing flows.
**Prevention:** Maintain an allowlist of safe redirect paths, normalize and validate `return_to` values against this allowlist, and default to a safe home dashboard when validation fails.

## 2025-12-05 - Missing Rate Limiting on Login Endpoint
**Vulnerability:** The login endpoint lacked IP and account-based rate limits, allowing high-volume credential stuffing without meaningful friction.
**Learning:** Authentication endpoints must be treated as high-value choke points and protected accordingly.
**Prevention:** Implement IP-based and account-based throttling with exponential backoff, and integrate with monitoring/alerting to surface abnormal login patterns.

## 2026-02-11 - Unsafe Deserialization in Job Worker
**Vulnerability:** The background job worker deserialized untrusted payloads using a generic object deserializer, allowing potential code execution when certain classes were present.
**Learning:** Deserializing untrusted data is inherently dangerous, especially with general-purpose object mappers.
**Prevention:** Restrict deserialization to a safe, explicitly allowed schema; avoid deserializing polymorphic types from untrusted sources and prefer structured formats (JSON with strict validation) over generic object graphs.

## 2026-04-03 - Overly Broad S3 Bucket Permissions
**Vulnerability:** The S3 bucket used for user uploads permitted public `list` access due to an overly permissive bucket policy.
**Learning:** Cloud storage permissions are easy to misconfigure and often remain unnoticed until a breach or audit.
**Prevention:** Apply least-privilege bucket policies, enforce private-by-default object ACLs, and add periodic automated checks for public exposure.

## 2026-06-29 - CSRF on Account Email Change
**Vulnerability:** The account email change endpoint was protected only by cookies and lacked CSRF defenses, allowing attackers to trigger email changes via crafted links.
**Learning:** Any state-changing action that relies on ambient authentication (cookies, headers) must be protected against CSRF.
**Prevention:** Implement synchronized tokens or same-site-safe CSRF protections on all sensitive POST/PUT/PATCH/DELETE endpoints, and verify origin headers where applicable.

## 2025-02-17 - [Incomplete Blocklist & Nested Archive Evasion]
**Vulnerability:** The Media Analyzer's blocklist missed critical dangerous extensions (.vbe, .iso, .img, .lnk) and failed to detect nested archives (e.g. zip inside zip), allowing malware evasion.
**Learning:** Blocklists are often incomplete and attackers use obscure extensions or nesting to bypass simple checks. Recursive analysis or flagging nested structures is essential.
**Prevention:** Use comprehensive extension lists (including Windows script/shortcut types and disk images) and implement depth-limited recursive inspection for archives.

## 2026-05-20 - Missing DMARC Validation Gap
**Vulnerability:** The Spam Analyzer verified SPF and DKIM results but ignored DMARC policy failures, allowing spoofed emails that passed individual checks (e.g. unaligned) to bypass detection.
**Learning:** Checking SPF and DKIM in isolation is insufficient for modern email security; DMARC is the policy layer that ties them to the domain identity.
**Prevention:** Always validate the 'dmarc' result in Authentication-Results headers and treat failures as high-confidence indicators of spoofing.
